//! Full HTTP/2 connection session: framing, HPACK, flow control,
//! RFC 9218 priority scheduling and the application event queue.
//!
//! The session is generic over [`crate::courierust_io::Read`]/[`crate::courierust_io::Write`]
//! and owns all per-connection state, so the same code runs over TCP or
//! an external TLS stream. Applications drive it with [`Connection::poll`]
//! (one frame per call) and drain [`Event`]s; outbound requests go
//! through `send_*`.

use crate::courierust_bytes::{Bytes, BytesMut};
use crate::courierust_error::{Error, ErrorKind, Result};
use crate::courierust_h2::error::ErrorCode;
use crate::courierust_h2::flow::FlowWindow;
use crate::courierust_h2::frame::{self, Frame, FrameHeader};
use crate::courierust_h2::priority::{Priority, Scheduler};
use crate::courierust_h2::settings::{Setting, Settings};
use crate::courierust_h2::stream::{Stream, StreamMap, StreamState};
use crate::courierust_hpack::{Decoder, Encoder, HeaderList};
use crate::courierust_io::{BufReader, BufWriter, Read, Write};
use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::ToString;
use alloc::vec::Vec;

/// Whether `buf` holds the HTTP/2 client connection preface.
#[inline]
pub fn is_preface(buf: &[u8]) -> bool {
    buf == frame::CLIENT_PREFACE
}

/// Connection configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// Whether this endpoint is a client (odd stream ids, sends preface).
    pub client: bool,
    /// The settings this endpoint advertises.
    pub local_settings: Settings,
    /// Scheduler DRR quantum in bytes per urgency bucket.
    pub scheduler_quantum: u32,
    /// Per-stream outbound buffer cap (bytes). Exceeding it makes
    /// `send_data` fail with `Overflow`, so callers can apply their own
    /// backpressure.
    pub max_send_buffer: usize,
    /// When true, received `DATA` credit is released to the peer
    /// immediately (suitable for clients that always drain bodies).
    pub auto_release_credit: bool,
}

/// Maximum flow-control window, 2^31-1 octets (RFC 9113 §6.9.1). A
/// window must never exceed this; WINDOW_UPDATEs that would push it past
/// the ceiling are a connection error of type FLOW_CONTROL_ERROR.
pub(crate) const MAX_FLOW_WINDOW: i64 = 0x7fff_ffff;

impl Default for Config {
    fn default() -> Self {
        Self {
            client: true,
            local_settings: Settings::default(),
            scheduler_quantum: 32 * 1024,
            max_send_buffer: 4 * 1024 * 1024,
            auto_release_credit: true,
        }
    }
}

/// Application-visible connection events (inbound messages).
#[derive(Debug, Clone)]
pub enum Event {
    /// A complete request (server) or response (client) header block.
    Headers {
        /// Stream id.
        stream_id: u32,
        /// Decoded fields.
        headers: HeaderList,
        /// Whether the stream ends with these headers (no body).
        end_stream: bool,
        /// Priority signaled with the headers (RFC 9218 / default).
        priority: Priority,
    },
    /// A `DATA` payload.
    Data {
        /// Stream id.
        stream_id: u32,
        /// Payload bytes.
        data: Bytes,
        /// Whether this ends the stream.
        end_stream: bool,
    },
    /// Trailing header block (ends the stream).
    Trailers {
        /// Stream id.
        stream_id: u32,
        /// Trailer fields.
        headers: HeaderList,
    },
    /// `RST_STREAM` received.
    Rst {
        /// Stream id.
        stream_id: u32,
        /// Error code.
        error_code: ErrorCode,
    },
    /// A stream-level error detected locally (RFC 9113 §5.4.2). The
    /// session sent `RST_STREAM` and terminated the stream; this is NOT a
    /// connection error, so the rest of the connection stays usable.
    StreamError {
        /// Stream id.
        stream_id: u32,
        /// Error code sent in the `RST_STREAM`.
        error_code: ErrorCode,
        /// Human-readable reason.
        message: alloc::string::String,
    },
    /// `GOAWAY` received.
    GoAway {
        /// Error code.
        error_code: ErrorCode,
        /// Last processed peer stream id.
        last_stream_id: u32,
        /// Debug data.
        debug: Bytes,
    },
    /// Peer `SETTINGS` applied.
    PeerSettings(Settings),
    /// A non-ACK `PING` (the session already queued the ACK).
    Ping {
        /// 8-byte opaque data.
        data: [u8; 8],
    },
    /// RFC 9218 `PRIORITY_UPDATE` received.
    PriorityUpdate {
        /// Prioritized stream id.
        stream_id: u32,
        /// New priority.
        priority: Priority,
    },
    /// A stream fully closed (useful for cleanup).
    StreamClosed {
        /// Stream id.
        stream_id: u32,
    },
}

/// A chunk of outbound body data waiting for flow-control credit.
struct Chunk {
    data: Bytes,
    end_stream: bool,
    /// When set, this final chunk is delivered as a trailing HEADERS
    /// block (RFC 9113 §8.1) instead of an empty END_STREAM DATA frame.
    trailers: Option<HeaderList>,
}

/// A partially-received header block (HEADERS + CONTINUATION).
struct PendingHeaders {
    stream_id: u32,
    block: BytesMut,
    end_stream: bool,
}

/// A frame being read across polls.
///
/// The transport may deliver the 9-byte frame header and the payload in
/// separate segments. We never discard a partially-read frame on a
/// timeout — the header bytes already consumed are kept here and the
/// read resumes on the next `poll`. Without this, a timeout between
/// header and payload would misparse payload bytes as a frame header
/// (frame desync) and kill the connection.
struct FrameReader {
    /// Partial frame header (first `hdr_len` bytes valid).
    hdr: [u8; 9],
    hdr_len: usize,
    /// Parsed header once complete.
    header: Option<FrameHeader>,
    /// Payload buffer (resized to `payload_len` once the header is known;
    /// reused across frames so steady-state decoding allocates once).
    payload: BytesMut,
    /// Total payload length expected.
    payload_len: usize,
    /// How many payload bytes have been read so far.
    payload_filled: usize,
}

impl Default for FrameReader {
    fn default() -> Self {
        Self {
            hdr: [0u8; 9],
            hdr_len: 0,
            header: None,
            payload: BytesMut::new(),
            payload_len: 0,
            payload_filled: 0,
        }
    }
}

/// HTTP/2 connection session.
pub struct Connection<R, W> {
    reader: BufReader<R>,
    writer: BufWriter<W>,
    config: Config,

    // HPACK
    encoder: Encoder,
    decoder: Decoder,

    // Settings state
    local: Settings,
    peer: Settings,
    settings_sent: bool,

    // Outbound
    preface_pending: bool,
    pending_frames: VecDeque<Frame>,

    // Inbound header block reassembly
    pending_headers: Option<PendingHeaders>,

    // Inbound frame accumulation (header + payload across polls)
    frame: FrameReader,

    // Streams + scheduling
    streams: StreamMap,
    scheduler: Scheduler,
    scheduled: alloc::collections::BTreeSet<u32>,
    send_queue: BTreeMap<u32, VecDeque<Chunk>>,
    pending_priority: BTreeMap<u32, Priority>,

    // Connection-level flow control
    conn_send_window: FlowWindow,
    conn_recv_window: FlowWindow,
    conn_pending_release: i64,

    // Events
    events: VecDeque<Event>,

    // Lifecycle
    goaway_sent: bool,
    goaway_received: bool,
    peer_last_stream: u32,
    closed: bool,
    // True until the peer ACKs our SETTINGS. RFC 9113 §6.5.3: a peer
    // that never acknowledges is a liveness failure; drivers enforce a
    // wall-clock deadline via [`Connection::settings_ack_pending`].
    settings_ack_pending: bool,
}

impl<R: Read, W: Write> Connection<R, W> {
    /// Create a connection session. For a client this queues the
    /// connection preface; for a server the caller must have already
    /// consumed and verified the client's preface.
    pub fn new(reader: R, writer: W, config: Config) -> Self {
        let is_client = config.client;
        let quantum = config.scheduler_quantum;
        let peer = Settings::default();
        let local = config.local_settings.clone();
        let conn_window = 65535i64;
        Self {
            reader: BufReader::new(reader, 16 * 1024),
            writer: BufWriter::new(writer, 16 * 1024),
            config,
            encoder: Encoder::new(),
            decoder: Decoder::new(
                local.header_table_size as usize,
                local.max_header_list_size as usize,
            ),
            preface_pending: is_client,
            local,
            peer,
            settings_sent: false,
            pending_frames: VecDeque::new(),
            pending_headers: None,
            frame: FrameReader::default(),
            streams: StreamMap::new(is_client),
            scheduler: Scheduler::new(quantum),
            scheduled: alloc::collections::BTreeSet::new(),
            send_queue: BTreeMap::new(),
            pending_priority: BTreeMap::new(),
            conn_send_window: FlowWindow::new(conn_window, MAX_FLOW_WINDOW),
            conn_recv_window: FlowWindow::new(conn_window, MAX_FLOW_WINDOW),
            conn_pending_release: 0,
            events: VecDeque::new(),
            goaway_sent: false,
            goaway_received: false,
            peer_last_stream: 0,
            closed: false,
            settings_ack_pending: true,
        }
    }

    /// Like [`Connection::new`], but pre-seeds the reader with bytes
    /// already read from the transport (RFC 7540 §3.2 `h2c` Upgrade: the
    /// server's SETTINGS may trail the `101` response in the same read).
    pub fn new_with_seed(reader: R, writer: W, config: Config, seed: &[u8]) -> Self {
        let mut conn = Self::new(reader, writer, config);
        conn.reader.seed(seed);
        conn
    }

    /// Register stream 1 for an RFC 7540 §3.2 `h2c` Upgrade. The upgraded
    /// HTTP/1.1 request occupies stream 1:
    ///
    /// * **Client** — stream 1 is half-closed locally (the request was
    ///   already sent as HTTP/1.1); the server's response arrives on it.
    /// * **Server** — stream 1 is half-closed remotely (the client's
    ///   request is complete); the response is sent on it.
    ///
    /// Must be called before the peer's response/request HEADERS are
    /// processed.
    pub fn register_upgrade_stream(&mut self) -> Result<()> {
        if self.goaway_received {
            return Err(Error::canceled("peer sent GOAWAY"));
        }
        self.streams.reserve_upgrade_stream();
        let initial = self.local.initial_window_size as i64;
        let mut s = Stream::new(
            1,
            self.peer.initial_window_size as i64,
            initial,
            Priority::default(),
        );
        if self.config.client {
            s.state = StreamState::HalfClosedLocal;
            s.send_done = true;
        } else {
            s.state = StreamState::HalfClosedRemote;
            s.recv_ended = true;
        }
        self.streams.insert(s);
        Ok(())
    }

    // ------------------------------------------------------------------
    // Public API
    // ------------------------------------------------------------------

    /// Whether the peer sent (or we sent) GOAWAY.
    #[inline]
    pub fn is_shutting_down(&self) -> bool {
        self.goaway_sent || self.goaway_received
    }

    /// Whether the session is fully closed.
    #[inline]
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Whether the peer has not yet acknowledged our SETTINGS. Drivers
    /// use this to enforce a `SETTINGS_TIMEOUT` connection error when the
    /// peer never ACKs within a reasonable wall-clock window.
    #[inline]
    pub fn settings_ack_pending(&self) -> bool {
        self.settings_ack_pending && !self.goaway_sent
    }

    /// Whether no work is pending (no outbound frames, no buffered data,
    /// no events). Drivers use this to decide when to sleep.
    pub fn is_idle(&self) -> bool {
        self.pending_frames.is_empty()
            && self.send_queue.iter().all(|(_, q)| q.is_empty())
            && self.events.is_empty()
    }

    /// Pop the next event, if any.
    #[inline]
    pub fn next_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    /// Whether events are pending.
    #[inline]
    pub fn has_events(&self) -> bool {
        !self.events.is_empty()
    }

    /// Current peer settings.
    #[inline]
    pub fn peer_settings(&self) -> &Settings {
        &self.peer
    }

    /// Current local settings.
    #[inline]
    pub fn local_settings(&self) -> &Settings {
        &self.local
    }

    /// The highest peer-initiated stream id observed.
    #[inline]
    pub fn last_peer_stream(&self) -> u32 {
        self.streams.last_peer_id()
    }

    /// Process one I/O step: flush outbound, read+process one frame,
    /// flush again. Returns `true` if any work happened (a frame was
    /// read or outbound frames were flushed). Transport timeouts /
    /// would-block are treated as "no data yet" and return `Ok(false)`.
    pub fn poll(&mut self) -> Result<bool> {
        self.poll_available(1)
    }

    /// Flush outbound data and process up to `max_frames` complete inbound
    /// frames that are already available on the transport.
    ///
    /// The old driver contract processed exactly one frame per call. That
    /// made a multiplexed connection pay a full read/timeout/flush cycle for
    /// every SETTINGS, HEADERS, and DATA frame, even when the peer had
    /// already written the whole response. Batching is deliberately bounded
    /// so a busy peer cannot starve command handling or response dispatch.
    /// A transport timeout ends the batch; it is not a connection error.
    pub fn poll_available(&mut self, max_frames: usize) -> Result<bool> {
        if self.closed {
            return Ok(false);
        }
        let had_pending = !self.pending_frames.is_empty();
        self.flush_outbound()?;
        let mut read_any = false;
        for _ in 0..max_frames.max(1) {
            match self.read_and_process_one() {
                Ok(true) => read_any = true,
                Ok(false) => break,
                Err(e) if e.kind == ErrorKind::Timeout => break,
                Err(e) if e.kind == ErrorKind::UnexpectedEof => {
                    self.closed = true;
                    return Err(e);
                }
                Err(e) => {
                    self.flush_final();
                    return Err(e);
                }
            }
            if self.reader.buffered() < 9 && self.frame.header.is_none() && self.frame.hdr_len == 0
            {
                break;
            }
        }
        self.flush_outbound()?;
        Ok(had_pending || read_any)
    }

    /// Best-effort flush of queued control frames (e.g. GOAWAY) even after
    /// the session is marked closed.
    fn flush_final(&mut self) {
        while let Some(f) = self.pending_frames.pop_front() {
            let mut buf = BytesMut::with_capacity(64);
            f.encode(&mut buf);
            if self.writer.write_all(buf.as_slice()).is_err() {
                break;
            }
        }
        let _ = self.writer.flush();
    }

    /// Flush pending outbound frames to the transport.
    pub fn flush(&mut self) -> Result<()> {
        self.flush_outbound()
    }

    /// Send a header block on a stream (request on the client, response
    /// on the server). The stream must already exist (client: via
    /// [`Connection::open_request`]; server: created by inbound HEADERS).
    pub fn send_headers(
        &mut self,
        stream_id: u32,
        fields: &HeaderList,
        end_stream: bool,
    ) -> Result<()> {
        if self.goaway_sent || self.closed {
            return Err(Error::canceled("connection closing"));
        }
        let mut block = BytesMut::with_capacity(64);
        self.encoder.encode(fields, &mut block);
        let max = self.peer.max_frame_size as usize;
        let method = fields
            .iter()
            .find(|f| f.name.as_str() == ":method")
            .and_then(|f| f.value.to_str().ok())
            .unwrap_or("");

        let now_closed = {
            let stream = self
                .streams
                .get_mut(&stream_id)
                .ok_or_else(|| Error::protocol("send_headers: unknown stream"))?;
            stream.body_expected = method != "HEAD" && method != "CONNECT";
            if stream.state == StreamState::Idle {
                stream.state = if end_stream {
                    StreamState::HalfClosedLocal
                } else {
                    StreamState::Open
                };
            } else if end_stream {
                stream.state = match stream.state {
                    StreamState::Open => StreamState::HalfClosedLocal,
                    StreamState::HalfClosedRemote => StreamState::Closed,
                    s => s,
                };
            }
            stream.send_done = end_stream;
            stream.state == StreamState::Closed
        };

        if now_closed {
            self.events.push_back(Event::StreamClosed { stream_id });
            self.close_stream(stream_id);
        }

        // Split the block into HEADERS + CONTINUATION frames.
        if block.len() <= max {
            self.pending_frames.push_back(Frame::Headers {
                stream_id,
                block: Bytes::from(block.into_vec()),
                end_stream,
                end_headers: true,
                priority: None,
            });
        } else {
            let head = block.split_to(max);
            self.pending_frames.push_back(Frame::Headers {
                stream_id,
                block: Bytes::from(head.into_vec()),
                end_stream,
                end_headers: false,
                priority: None,
            });
            while !block.is_empty() {
                let end = block.len() <= max;
                let part = block.split_to(core::cmp::min(max, block.len()));
                self.pending_frames.push_back(Frame::Continuation {
                    stream_id,
                    end_headers: end,
                    block: Bytes::from(part.into_vec()),
                });
            }
        }
        Ok(())
    }

    /// Allocate a client stream id and open its record (client only).
    /// Call before [`Connection::send_headers`].
    pub fn open_request(&mut self, priority: Priority) -> Result<u32> {
        if !self.config.client {
            return Err(Error::protocol("open_request on server session"));
        }
        if self.goaway_received {
            return Err(Error::canceled("peer sent GOAWAY"));
        }
        let id = self
            .streams
            .allocate_client_id()
            .ok_or_else(|| Error::protocol("stream id space exhausted"))?;
        let initial = self.local.initial_window_size as i64;
        let s = Stream::new(id, self.peer.initial_window_size as i64, initial, priority);
        self.streams.insert(s);
        Ok(id)
    }

    /// Queue body data for a stream. Returns the number of bytes
    /// accepted (all of them, unless the per-stream buffer cap was
    /// hit, in which case nothing is accepted and `Overflow` is
    /// returned).
    pub fn send_data(&mut self, stream_id: u32, data: Bytes, end_stream: bool) -> Result<usize> {
        if self.goaway_sent || self.closed {
            return Err(Error::canceled("connection closing"));
        }
        let data_len = data.len();
        let stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or_else(|| Error::protocol("send_data: unknown stream"))?;
        if !stream.can_send() {
            return Err(Error::canceled("stream not writable"));
        }
        let buffered: usize = self
            .send_queue
            .get(&stream_id)
            .map(|q| q.iter().map(|c| c.data.len()).sum())
            .unwrap_or(0);
        if buffered + data_len > self.config.max_send_buffer {
            return Err(Error::overflow("per-stream send buffer full"));
        }
        stream.send_buffered += data_len;
        if end_stream {
            stream.send_done = true;
        }
        self.send_queue
            .entry(stream_id)
            .or_default()
            .push_back(Chunk {
                data,
                end_stream,
                trailers: None,
            });
        self.maybe_schedule(stream_id);
        Ok(data_len)
    }

    /// Queue a trailing header block for a stream (RFC 9113 §8.1). The
    /// trailers are sent only after every previously queued DATA chunk on
    /// the stream has been emitted (they ride in the same flow-controlled
    /// send queue), and they end the stream. Trailer fields must not
    /// contain pseudo-headers.
    pub fn send_trailers(&mut self, stream_id: u32, fields: &HeaderList) -> Result<()> {
        if self.goaway_sent || self.closed {
            return Err(Error::canceled("connection closing"));
        }
        let stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or_else(|| Error::protocol("send_trailers: unknown stream"))?;
        if !stream.can_send() {
            return Err(Error::canceled("stream not writable"));
        }
        stream.send_done = true;
        self.send_queue
            .entry(stream_id)
            .or_default()
            .push_back(Chunk {
                data: Bytes::new(),
                end_stream: true,
                trailers: Some(fields.clone()),
            });
        self.maybe_schedule(stream_id);
        Ok(())
    }

    /// Send RST_STREAM.
    pub fn send_rst(&mut self, stream_id: u32, code: ErrorCode) {
        if self.closed {
            return;
        }
        self.pending_frames.push_back(Frame::RstStream {
            stream_id,
            error_code: code,
        });
        self.close_stream(stream_id);
    }

    /// Send a PING (non-ACK).
    pub fn send_ping(&mut self, data: [u8; 8]) {
        if self.closed {
            return;
        }
        self.pending_frames
            .push_back(Frame::Ping { ack: false, data });
    }

    /// Send GOAWAY and stop accepting new work.
    pub fn send_goaway(&mut self, code: ErrorCode, debug: &[u8]) {
        if self.goaway_sent || self.closed {
            return;
        }
        self.goaway_sent = true;
        self.pending_frames.push_back(Frame::GoAway {
            last_stream_id: self.streams.last_peer_id(),
            error_code: code,
            debug: Bytes::from(debug),
        });
    }

    /// Send an RFC 9218 PRIORITY_UPDATE (client only).
    pub fn send_priority_update(&mut self, stream_id: u32, priority: Priority) -> Result<()> {
        if !self.config.client {
            return Err(Error::protocol("servers must not send PRIORITY_UPDATE"));
        }
        if self.closed {
            return Err(Error::canceled("connection closing"));
        }
        self.pending_frames.push_back(Frame::PriorityUpdate {
            prioritized_stream_id: stream_id,
            priority_field: Bytes::from(priority.to_string().into_bytes()),
        });
        if let Some(s) = self.streams.get_mut(&stream_id) {
            s.priority = priority;
        }
        Ok(())
    }

    /// Release received-data credit back to the peer (BCR). Batches
    /// WINDOW_UPDATE frames.
    pub fn release_data(&mut self, stream_id: u32, n: usize) {
        let n = n as i64;
        let stream_release_threshold = (self.local.initial_window_size as i64 / 2).max(16 * 1024);
        let mut emit_stream = 0i64;
        if let Some(s) = self.streams.get_mut(&stream_id) {
            if s.recv_unreleased >= stream_release_threshold {
                emit_stream = s.recv_unreleased;
                s.recv_unreleased = 0;
                s.recv_window = s
                    .recv_window
                    .saturating_add(emit_stream)
                    .min(MAX_FLOW_WINDOW);
            }
        }
        if emit_stream > 0 {
            self.pending_frames.push_back(Frame::WindowUpdate {
                stream_id,
                increment: emit_stream.min(i64::from(u32::MAX)) as u32,
            });
        }

        self.conn_pending_release += n;
        let conn_threshold = 32 * 1024i64;
        if self.conn_pending_release >= conn_threshold {
            let inc = self.conn_pending_release.min(i64::from(u32::MAX)) as u32;
            self.conn_pending_release = 0;
            self.conn_recv_window.release(inc as i64);
            self.pending_frames.push_back(Frame::WindowUpdate {
                stream_id: 0,
                increment: inc,
            });
        }
    }

    // ------------------------------------------------------------------
    // Outbound flush + scheduling
    // ------------------------------------------------------------------

    fn flush_outbound(&mut self) -> Result<()> {
        if self.closed {
            return Ok(());
        }
        if self.preface_pending {
            self.writer.write_all(frame::CLIENT_PREFACE)?;
            self.preface_pending = false;
        }
        if !self.settings_sent {
            self.queue_settings();
            self.settings_sent = true;
        }
        // Emit body data for scheduled streams.
        self.emit_data_frames()?;
        while let Some(f) = self.pending_frames.pop_front() {
            let mut buf = BytesMut::with_capacity(64);
            f.encode(&mut buf);
            self.writer.write_all(buf.as_slice())?;
        }
        self.writer.flush()?;
        Ok(())
    }

    fn queue_settings(&mut self) {
        let entries = self.local.to_vec();
        self.pending_frames.push_back(Frame::Settings {
            ack: false,
            entries,
        });
    }

    /// Emit DATA frames for scheduled streams, bounded per flush for fairness
    fn emit_data_frames(&mut self) -> Result<()> {
        if self.conn_send_window.available() <= 0 {
            return Ok(());
        }
        let max_frame = self.peer.max_frame_size as i64;
        for _ in 0..64 {
            let want = max_frame as usize;
            let sid = match self.scheduler.next(want) {
                Some(s) => s,
                None => break,
            };

            self.scheduled.remove(&sid);
            let can_send = {
                let s = match self.streams.get(&sid) {
                    Some(s) => s,
                    None => {
                        self.scheduler.remove(sid);
                        continue;
                    }
                };
                s.send_window > 0
            };
            if !can_send {
                self.scheduler.remove(sid);
                self.scheduled.remove(&sid);
                continue;
            }
            let stream_window = self.streams.get(&sid).map(|s| s.send_window).unwrap_or(0);
            let amount = stream_window
                .min(self.conn_send_window.available())
                .min(max_frame)
                .max(0) as usize;
            if amount == 0 {
                self.scheduler.remove(sid);
                self.scheduled.remove(&sid);
                continue;
            }
            let payload;
            {
                let q = match self.send_queue.get_mut(&sid) {
                    Some(q) => q,
                    None => {
                        self.scheduler.remove(sid);
                        self.scheduled.remove(&sid);
                        continue;
                    }
                };
                let chunk = match q.front_mut() {
                    Some(c) => c,
                    None => {
                        self.scheduler.remove(sid);
                        self.scheduled.remove(&sid);
                        continue;
                    }
                };
                let take = core::cmp::min(amount, chunk.data.len());
                payload = chunk.data.split_to(take);
            }

            let mut end_stream = false;
            let mut trailers: Option<HeaderList> = None;
            if let Some(q) = self.send_queue.get_mut(&sid) {
                let front_empty = q.front().map(|c| c.data.is_empty()).unwrap_or(false);
                if front_empty {
                    let popped = q.pop_front().unwrap();
                    end_stream = popped.end_stream && q.is_empty();
                    if end_stream {
                        trailers = popped.trailers;
                    }
                }
            }
            {
                let s = self.streams.get_mut(&sid).unwrap();
                s.send_window -= payload.len() as i64;
                s.send_buffered = s.send_buffered.saturating_sub(payload.len());
            }
            self.conn_send_window.consume(payload.len() as i64);
            if let Some(fields) = trailers {
                self.emit_trailer_block(sid, &fields);
                end_stream = true;
            } else {
                self.pending_frames.push_back(Frame::Data {
                    stream_id: sid,
                    data: payload,
                    end_stream,
                });
            }

            if end_stream {
                let remote_done = self
                    .streams
                    .get(&sid)
                    .map(|s| s.state == StreamState::HalfClosedRemote)
                    .unwrap_or(false);
                if remote_done {
                    self.events
                        .push_back(Event::StreamClosed { stream_id: sid });
                    self.close_stream(sid);
                    continue;
                }
                let s = self.streams.get_mut(&sid).unwrap();
                if s.state == StreamState::Open {
                    s.state = StreamState::HalfClosedLocal;
                }
            }

            let stream = self.streams.get(&sid).unwrap();
            let exhausted = self
                .send_queue
                .get(&sid)
                .map(|q| q.is_empty())
                .unwrap_or(true);
            if !exhausted && stream.send_window > 0 {
                self.maybe_schedule(sid);
            } else if exhausted {
                self.scheduler.remove(sid);
                self.scheduled.remove(&sid);
            }
        }
        Ok(())
    }

    /// Encode and queue a trailing HEADERS block for the given stream
    fn emit_trailer_block(&mut self, stream_id: u32, fields: &HeaderList) {
        let mut block = BytesMut::with_capacity(64);
        self.encoder.encode(fields, &mut block);
        let max = self.peer.max_frame_size as usize;
        if block.len() <= max {
            self.pending_frames.push_back(Frame::Headers {
                stream_id,
                block: Bytes::from(block.into_vec()),
                end_stream: true,
                end_headers: true,
                priority: None,
            });
        } else {
            let head = block.split_to(max);
            self.pending_frames.push_back(Frame::Headers {
                stream_id,
                block: Bytes::from(head.into_vec()),
                end_stream: true,
                end_headers: false,
                priority: None,
            });
            while !block.is_empty() {
                let end = block.len() <= max;
                let part = block.split_to(core::cmp::min(max, block.len()));
                self.pending_frames.push_back(Frame::Continuation {
                    stream_id,
                    end_headers: end,
                    block: Bytes::from(part.into_vec()),
                });
            }
        }
    }

    fn maybe_schedule(&mut self, stream_id: u32) {
        if self.scheduled.contains(&stream_id) {
            return;
        }
        // A stream is schedulable while it has buffered data and send
        // credit — even if `send_done` is set (END_STREAM is queued behind
        // the data).
        let has_data = self
            .send_queue
            .get(&stream_id)
            .map(|q| !q.is_empty())
            .unwrap_or(false);
        if !has_data {
            return;
        }
        let ok = match self.streams.get(&stream_id) {
            Some(s) => s.send_window > 0,
            None => false,
        };
        if !ok {
            return;
        }
        let p = self
            .streams
            .get(&stream_id)
            .map(|s| s.priority)
            .unwrap_or_default();
        self.scheduler.add(stream_id, p);
        self.scheduled.insert(stream_id);
    }

    // ------------------------------------------------------------------
    // Inbound
    // ------------------------------------------------------------------

    fn read_and_process_one(&mut self) -> Result<bool> {
        if self.frame.header.is_none() {
            let n = self
                .reader
                .read_more(&mut self.frame.hdr[self.frame.hdr_len..])?;
            self.frame.hdr_len += n;
            if self.frame.hdr_len < 9 {
                return Ok(false); // header still incomplete
            }
            let hdr = self.frame.hdr;
            self.frame.header = Some(FrameHeader {
                len: ((hdr[0] as u32) << 16) | ((hdr[1] as u32) << 8) | (hdr[2] as u32),
                kind: hdr[3],
                flags: hdr[4],
                stream_id: u32::from_be_bytes([hdr[5] & 0x7f, hdr[6], hdr[7], hdr[8]]),
            });
            let h = self.frame.header.as_ref().unwrap();
            if h.len > self.local.max_frame_size {
                self.send_goaway(ErrorCode::FrameSizeError, b"frame too large");
                self.closed = true;
                return Err(Error::h2(
                    ErrorCode::FrameSizeError.as_u32(),
                    "received frame exceeds our max frame size",
                ));
            }
            self.frame.payload_len = h.len as usize;
            self.frame.payload.clear();
            self.frame.payload.resize(self.frame.payload_len, 0);
            self.frame.payload_filled = 0;
        }

        if self.frame.payload_filled < self.frame.payload_len {
            let n = {
                let (reader, frame) = (&mut self.reader, &mut self.frame);
                let start = frame.payload_filled;
                let end = frame.payload_len;
                reader.read_more(&mut frame.payload[start..end])?
            };
            self.frame.payload_filled += n;
            if self.frame.payload_filled < self.frame.payload_len {
                return Ok(false); // payload still incomplete
            }
        }

        let header = self.frame.header.take().unwrap();
        let frame = match Frame::parse(
            header,
            self.frame.payload.as_slice(),
            self.local.max_frame_size,
        ) {
            Ok(f) => f,
            Err(e) => {
                let code = e
                    .h2_code()
                    .and_then(ErrorCode::from_u32)
                    .unwrap_or(ErrorCode::ProtocolError);
                return self.conn_error(code, &e.to_string()).map(|_| false);
            }
        };
        self.frame.header = None;
        self.frame.hdr_len = 0;
        self.frame.payload_len = 0;
        self.frame.payload_filled = 0;
        self.process_frame(frame)?;
        Ok(true)
    }

    fn process_frame(&mut self, frame: Frame) -> Result<()> {
        if self.pending_headers.is_some() {
            match frame {
                Frame::Continuation {
                    stream_id,
                    end_headers,
                    block,
                } => {
                    let pending = self.pending_headers.as_mut().unwrap();
                    if pending.stream_id != stream_id {
                        return self.conn_error(
                            ErrorCode::ProtocolError,
                            "CONTINUATION on different stream",
                        );
                    }
                    if pending.block.len() + block.len() > self.local.max_header_list_size as usize
                    {
                        return self.conn_error(
                            ErrorCode::CompressionError,
                            "header block exceeds advertised limit",
                        );
                    }
                    pending.block.extend_from_slice(block.as_slice());
                    if end_headers {
                        let p = self.pending_headers.take().unwrap();
                        self.finish_header_block(p)?;
                    }
                    return Ok(());
                }
                _ => {
                    return self.conn_error(ErrorCode::ProtocolError, "expected CONTINUATION");
                }
            }
        }

        match frame {
            Frame::Headers {
                stream_id,
                block,
                end_stream,
                end_headers,
                priority: _p,
            } => {
                if end_headers {
                    self.finish_header_block(PendingHeaders {
                        stream_id,
                        block: BytesMut::from_vec(block.into_vec()),
                        end_stream,
                    })
                } else {
                    self.pending_headers = Some(PendingHeaders {
                        stream_id,
                        block: BytesMut::from_vec(block.into_vec()),
                        end_stream,
                    });
                    Ok(())
                }
            }
            Frame::Data {
                stream_id,
                data,
                end_stream,
            } => self.on_data(stream_id, data, end_stream),
            Frame::RstStream {
                stream_id,
                error_code,
            } => {
                if !self.streams.contains(&stream_id) {
                    return self.conn_error(ErrorCode::ProtocolError, "RST_STREAM on idle stream");
                }
                self.events.push_back(Event::Rst {
                    stream_id,
                    error_code,
                });
                self.close_stream(stream_id);
                Ok(())
            }
            Frame::Settings { ack, entries } => {
                if ack {
                    if !entries.is_empty() {
                        return self
                            .conn_error(ErrorCode::FrameSizeError, "SETTINGS ACK with payload");
                    }
                    self.settings_ack_pending = false;
                    Ok(())
                } else {
                    self.on_settings(entries)
                }
            }
            Frame::Ping { ack, data } => {
                if ack {
                    Ok(())
                } else {
                    self.pending_frames
                        .push_back(Frame::Ping { ack: true, data });
                    self.events.push_back(Event::Ping { data });
                    Ok(())
                }
            }
            Frame::GoAway {
                last_stream_id,
                error_code,
                debug,
            } => {
                self.goaway_received = true;
                self.peer_last_stream = last_stream_id;
                self.events.push_back(Event::GoAway {
                    error_code,
                    last_stream_id,
                    debug,
                });
                // Streams above last_stream_id are implicitly failed.
                let ids: Vec<u32> = self
                    .streams
                    .iter()
                    .filter(|s| s.id > last_stream_id)
                    .map(|s| s.id)
                    .collect();
                for id in ids {
                    self.events.push_back(Event::Rst {
                        stream_id: id,
                        error_code: ErrorCode::RefusedStream,
                    });
                    self.close_stream(id);
                }
                Ok(())
            }
            Frame::WindowUpdate {
                stream_id,
                increment,
            } => self.on_window_update(stream_id, increment),
            Frame::Priority {
                stream_id,
                priority: _p,
            } => {
                let _ = stream_id;
                Ok(())
            }
            Frame::PriorityUpdate {
                prioritized_stream_id,
                priority_field,
            } => {
                if self.config.client {
                    return self.conn_error(
                        ErrorCode::ProtocolError,
                        "server must not send PRIORITY_UPDATE",
                    );
                }
                let priority = Priority::parse(priority_field.as_slice()).unwrap_or_default();
                if let Some(s) = self.streams.get_mut(&prioritized_stream_id) {
                    let old = s.priority;
                    s.priority = priority;
                    self.scheduler.update(prioritized_stream_id, old, priority);
                } else {
                    // Buffer the most recent update for an idle stream
                    // (RFC 9218 §7: bounded, most-recent wins).
                    if self.pending_priority.len() < 1024 {
                        self.pending_priority
                            .insert(prioritized_stream_id, priority);
                    } else {
                        self.pending_priority.clear();
                        self.pending_priority
                            .insert(prioritized_stream_id, priority);
                    }
                }
                self.events.push_back(Event::PriorityUpdate {
                    stream_id: prioritized_stream_id,
                    priority,
                });
                Ok(())
            }
            Frame::PushPromise { .. } => {
                self.conn_error(ErrorCode::ProtocolError, "unexpected PUSH_PROMISE")
            }
            Frame::Continuation { .. } => self.conn_error(
                ErrorCode::ProtocolError,
                "unexpected CONTINUATION without a pending header block",
            ),
            Frame::Unknown { .. } => Ok(()), // RFC 9113 §4.1: ignore
        }
    }

    fn finish_header_block(&mut self, p: PendingHeaders) -> Result<()> {
        let fields = match self.decoder.decode(p.block.as_slice()) {
            Ok(f) => f,
            Err(e) => {
                return self.conn_error(ErrorCode::CompressionError, &e.to_string());
            }
        };
        let sid = p.stream_id;
        let is_new = !self.streams.contains(&sid);

        if is_new {
            self.validate_header_block(&fields, !self.config.client, false)?;

            if self.config.client {
                return self.conn_error(ErrorCode::ProtocolError, "response on unknown stream");
            }
            if !self.streams.accept_peer_id(sid) {
                return self.conn_error(ErrorCode::ProtocolError, "non-monotonic stream id");
            }
            let max_conc = if self.local.max_concurrent_streams == 0 {
                usize::MAX
            } else {
                self.local.max_concurrent_streams as usize
            };
            if self.streams.open_count() >= max_conc {
                self.pending_frames.push_back(Frame::RstStream {
                    stream_id: sid,
                    error_code: ErrorCode::RefusedStream,
                });
                self.events
                    .push_back(Event::StreamClosed { stream_id: sid });
                return Ok(());
            }
            let initial = self.local.initial_window_size as i64;
            let priority = self
                .pending_priority
                .remove(&sid)
                .unwrap_or_else(|| Priority::parse_headers(&fields).unwrap_or_default());
            let cl = self.parse_content_length(&fields)?;
            let method = fields
                .iter()
                .find(|f| f.name.as_str() == ":method")
                .and_then(|f| f.value.to_str().ok())
                .unwrap_or("");
            let mut s = Stream::new(sid, self.peer.initial_window_size as i64, initial, priority);
            s.state = if p.end_stream {
                StreamState::HalfClosedRemote
            } else {
                StreamState::Open
            };
            if p.end_stream {
                s.recv_ended = true;
            }
            s.headers_delivered = true;
            s.content_length = cl;
            s.body_expected = method != "HEAD" && method != "CONNECT";
            self.streams.insert(s);
            if p.end_stream {
                self.verify_content_length(sid);
                if !self.streams.contains(&sid) {
                    return Ok(());
                }
            }
            self.events.push_back(Event::Headers {
                stream_id: sid,
                headers: fields,
                end_stream: p.end_stream,
                priority,
            });
            return Ok(());
        }

        let (is_closed, delivered) = {
            let s = self.streams.get(&sid).unwrap();
            (s.is_closed(), s.headers_delivered)
        };
        if is_closed {
            // Late frames on closed streams: reset.
            self.pending_frames.push_back(Frame::RstStream {
                stream_id: sid,
                error_code: ErrorCode::StreamClosed,
            });
            return Ok(());
        }
        if delivered {
            self.validate_header_block(&fields, false, true)?;
            self.verify_content_length(sid);
            if !self.streams.contains(&sid) {
                return Ok(());
            }
            self.events.push_back(Event::Trailers {
                stream_id: sid,
                headers: fields,
            });
            let closed = {
                let s = self.streams.get_mut(&sid).unwrap();
                s.recv_ended = true;
                s.state = match s.state {
                    StreamState::Open => StreamState::HalfClosedRemote,
                    StreamState::HalfClosedLocal => StreamState::Closed,
                    s => s,
                };
                s.state == StreamState::Closed
            };
            if closed {
                self.events
                    .push_back(Event::StreamClosed { stream_id: sid });
                self.close_stream(sid);
            }
            return Ok(());
        }
        if !self.config.client {
            return self.conn_error(
                ErrorCode::ProtocolError,
                "unexpected HEADERS on existing stream",
            );
        }
        self.validate_header_block(&fields, false, false)?;
        let cl = self.parse_content_length(&fields)?;
        let status = fields
            .iter()
            .find(|f| f.name.as_str() == ":status")
            .and_then(|f| f.value.to_str().ok())
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(200);
        let status_expects_body = !(100..=199).contains(&status) && status != 204 && status != 304;
        let priority;
        {
            let stream = self.streams.get_mut(&sid).unwrap();
            stream.content_length = cl;
            stream.body_expected = stream.body_expected && status_expects_body;
            stream.state = match stream.state {
                StreamState::Open => {
                    if p.end_stream {
                        StreamState::HalfClosedRemote
                    } else {
                        StreamState::Open
                    }
                }
                StreamState::HalfClosedLocal => {
                    if p.end_stream {
                        StreamState::Closed
                    } else {
                        StreamState::HalfClosedLocal
                    }
                }
                _ => {
                    return self.conn_error(ErrorCode::ProtocolError, "HEADERS in invalid state");
                }
            };
            if p.end_stream {
                stream.recv_ended = true;
            }
            priority = self
                .pending_priority
                .remove(&sid)
                .unwrap_or(stream.priority);
            stream.priority = priority;
            stream.headers_delivered = true;
        }
        if p.end_stream {
            self.verify_content_length(sid);
            if !self.streams.contains(&sid) {
                return Ok(());
            }
        }
        self.events.push_back(Event::Headers {
            stream_id: sid,
            headers: fields,
            end_stream: p.end_stream,
            priority,
        });
        if self.streams.get(&sid).is_some_and(|s| s.is_closed()) {
            self.events
                .push_back(Event::StreamClosed { stream_id: sid });
            self.close_stream(sid);
        }
        Ok(())
    }

    /// Validate an inbound header block against RFC 9113 §8.1.2:
    ///
    /// * Pseudo-headers must precede all regular fields.
    /// * Requests require `:method`, `:scheme` and `:path` (or, for
    ///   `CONNECT`, exactly `:authority`); responses require exactly one
    ///   three-digit `:status`.
    /// * No unknown pseudo-headers, and no cross-contamination of
    ///   request/response pseudo-headers.
    /// * Trailers must not contain pseudo-headers at all.
    ///
    /// Violations are connection errors (`PROTOCOL_ERROR`).
    fn validate_header_block(
        &mut self,
        fields: &HeaderList,
        is_request: bool,
        is_trailer: bool,
    ) -> Result<()> {
        let mut saw_regular = false;
        let mut method: Option<&str> = None;
        let mut has_scheme = false;
        let mut path: Option<&str> = None;
        let mut has_authority = false;
        let mut has_status = false;

        for f in fields.iter() {
            if !f.name.is_pseudo() {
                saw_regular = true;
                let n = f.name.as_str();
                if matches!(
                    n,
                    "connection"
                        | "keep-alive"
                        | "proxy-connection"
                        | "transfer-encoding"
                        | "upgrade"
                ) {
                    return self.conn_error(
                        ErrorCode::ProtocolError,
                        "connection-specific header in HTTP/2",
                    );
                }
                if n == "te" {
                    let v = f.value.to_str().unwrap_or("");
                    if !v.eq_ignore_ascii_case("trailers") {
                        return self
                            .conn_error(ErrorCode::ProtocolError, "TE header must be 'trailers'");
                    }
                }
                if is_trailer && matches!(n, "content-length" | "host" | "trailer" | "te") {
                    return self.conn_error(ErrorCode::ProtocolError, "framing field in trailers");
                }
                continue;
            }
            if saw_regular {
                return self.conn_error(
                    ErrorCode::ProtocolError,
                    "pseudo-header after regular field",
                );
            }
            if is_trailer {
                return self.conn_error(ErrorCode::ProtocolError, "pseudo-header in trailers");
            }
            match f.name.as_str() {
                ":method" => {
                    if !is_request {
                        return self.conn_error(ErrorCode::ProtocolError, ":method in response");
                    }
                    method = f.value.to_str().ok();
                }
                ":scheme" => {
                    if !is_request {
                        return self.conn_error(ErrorCode::ProtocolError, ":scheme in response");
                    }
                    has_scheme = true;
                }
                ":path" => {
                    if !is_request {
                        return self.conn_error(ErrorCode::ProtocolError, ":path in response");
                    }
                    path = f.value.to_str().ok();
                }
                ":authority" => {
                    if !is_request {
                        return self.conn_error(ErrorCode::ProtocolError, ":authority in response");
                    }
                    has_authority = true;
                }
                ":status" => {
                    if is_request {
                        return self.conn_error(ErrorCode::ProtocolError, ":status in request");
                    }
                    if has_status {
                        return self.conn_error(ErrorCode::ProtocolError, "duplicate :status");
                    }
                    has_status = true;
                    let v = f.value.as_bytes();
                    let ok = v.len() == 3
                        && v[0].is_ascii_digit()
                        && v[1].is_ascii_digit()
                        && v[2].is_ascii_digit()
                        && v[0] >= b'1'
                        && v[0] <= b'5';
                    if !ok {
                        return self.conn_error(ErrorCode::ProtocolError, "invalid :status value");
                    }
                }
                _ => {
                    return self.conn_error(ErrorCode::ProtocolError, "unknown pseudo-header");
                }
            }
        }
        if is_trailer {
            return Ok(());
        }
        if is_request {
            let is_connect = method == Some("CONNECT");
            if is_connect {
                if has_scheme || path.is_some() {
                    return self.conn_error(
                        ErrorCode::ProtocolError,
                        "CONNECT must not carry :scheme or :path",
                    );
                }
                if !has_authority {
                    return self
                        .conn_error(ErrorCode::ProtocolError, "CONNECT requires :authority");
                }
            } else {
                if method.is_none() {
                    return self.conn_error(ErrorCode::ProtocolError, "request missing :method");
                }
                if !has_scheme {
                    return self.conn_error(ErrorCode::ProtocolError, "request missing :scheme");
                }
                match path {
                    None => {
                        return self.conn_error(ErrorCode::ProtocolError, "request missing :path");
                    }
                    Some("") => {
                        return self.conn_error(ErrorCode::ProtocolError, "empty :path");
                    }
                    _ => {}
                }
            }
        } else if !has_status {
            return self.conn_error(ErrorCode::ProtocolError, "response missing :status");
        }
        Ok(())
    }

    fn on_data(&mut self, stream_id: u32, data: Bytes, end_stream: bool) -> Result<()> {
        if !self.streams.contains(&stream_id) {
            return self.conn_error(ErrorCode::ProtocolError, "DATA on unknown stream");
        }
        let len = data.len() as i64;
        let bodyless = self
            .streams
            .get(&stream_id)
            .map(|s| !s.body_expected)
            .unwrap_or(false);
        if bodyless {
            self.stream_error(
                stream_id,
                ErrorCode::ProtocolError,
                "DATA on bodyless message",
            );
            return Ok(());
        }
        let mut len_overflow = false;
        {
            let s = self.streams.get_mut(&stream_id).unwrap();
            if !s.can_recv() {
                self.pending_frames.push_back(Frame::RstStream {
                    stream_id,
                    error_code: ErrorCode::StreamClosed,
                });
                return Ok(());
            }
            if s.recv_window < len {
                return self.conn_error(ErrorCode::FlowControlError, "stream window exceeded");
            }
            s.recv_window -= len;
            s.recv_unreleased += len;
            match s.recv_body_len.checked_add(data.len() as u64) {
                Some(n) => s.recv_body_len = n,
                None => len_overflow = true,
            }
            if end_stream {
                s.recv_ended = true;
                s.state = match s.state {
                    StreamState::Open => StreamState::HalfClosedRemote,
                    StreamState::HalfClosedLocal => StreamState::Closed,
                    s => s,
                };
            }
        }
        if len_overflow {
            self.stream_error(
                stream_id,
                ErrorCode::ProtocolError,
                "content-length counter overflow",
            );
            return Ok(());
        }
        if self.conn_recv_window.available() < len {
            return self.conn_error(ErrorCode::FlowControlError, "connection window exceeded");
        }
        self.conn_recv_window.consume(len);
        if end_stream {
            self.verify_content_length(stream_id);
            if !self.streams.contains(&stream_id) {
                // verify_content_length reset the stream.
                return Ok(());
            }
        }
        self.events.push_back(Event::Data {
            stream_id,
            data,
            end_stream,
        });
        if self.config.auto_release_credit {
            self.release_data(stream_id, len as usize);
        }
        if end_stream {
            let closed = self
                .streams
                .get(&stream_id)
                .map(|s| s.is_closed())
                .unwrap_or(false);
            if closed {
                self.events.push_back(Event::StreamClosed { stream_id });
                self.close_stream(stream_id);
            }
        }
        Ok(())
    }

    fn on_settings(&mut self, entries: Vec<Setting>) -> Result<()> {
        let mut new_settings = self.peer.clone();
        if let Err(e) = new_settings.apply(&entries) {
            return self.conn_error(ErrorCode::ProtocolError, &e.to_string());
        }

        if self.peer.no_rfc7540_priorities != new_settings.no_rfc7540_priorities
            && self.peer.no_rfc7540_priorities != 0
        {
            return self.conn_error(
                ErrorCode::ProtocolError,
                "SETTINGS_NO_RFC7540_PRIORITIES changed",
            );
        }
        self.encoder
            .set_peer_table_size(new_settings.header_table_size as usize);
        // Apply INITIAL_WINDOW_SIZE delta to every stream's send window.
        let delta = new_settings.initial_window_size as i64 - self.peer.initial_window_size as i64;
        if delta != 0 {
            let ids: Vec<u32> = self.streams.iter().map(|s| s.id).collect();
            for id in ids {
                let s = self.streams.get_mut(&id).unwrap();
                let next = s.send_window.saturating_add(delta);
                if next < i64::from(i32::MIN) {
                    return self
                        .conn_error(ErrorCode::FlowControlError, "initial window delta overflow");
                }
                s.send_window = next;
            }
        }
        self.peer = new_settings;
        self.pending_frames.push_back(Frame::Settings {
            ack: true,
            entries: Vec::new(),
        });
        self.events
            .push_back(Event::PeerSettings(self.peer.clone()));
        let ids: Vec<u32> = self
            .streams
            .iter()
            .filter(|s| s.send_buffered > 0)
            .map(|s| s.id)
            .collect();
        for id in ids {
            self.maybe_schedule(id);
        }
        Ok(())
    }

    fn on_window_update(&mut self, stream_id: u32, increment: u32) -> Result<()> {
        if stream_id == 0 {
            if !self.conn_send_window.increase(increment) {
                return self.conn_error(ErrorCode::FlowControlError, "connection window overflow");
            }

            let ids: Vec<u32> = self
                .streams
                .iter()
                .filter(|s| s.send_buffered > 0)
                .map(|s| s.id)
                .collect();
            for id in ids {
                self.maybe_schedule(id);
            }
        } else {
            let s = match self.streams.get_mut(&stream_id) {
                Some(s) => s,
                None => return Ok(()), // late update on a closed stream
            };
            let next = s.send_window.saturating_add(increment as i64);
            if next > MAX_FLOW_WINDOW {
                return self.conn_error(ErrorCode::FlowControlError, "stream window overflow");
            }
            s.send_window = next;
            self.maybe_schedule(stream_id);
        }
        Ok(())
    }

    /// Register a connection error: send GOAWAY, mark closed, and return
    /// an error carrying the code.
    fn conn_error(&mut self, code: ErrorCode, msg: &str) -> Result<()> {
        Err(self.protocol_err(code, msg))
    }

    /// Send GOAWAY, mark the connection closed, and return the error
    /// value. Unlike [`Self::conn_error`] this returns the [`Error`]
    /// directly, so it can be embedded in other error paths.
    fn protocol_err(&mut self, code: ErrorCode, msg: &str) -> Error {
        self.send_goaway(code, msg.as_bytes());
        self.closed = true;
        Error::h2(code.as_u32(), msg.to_string())
    }

    /// Surface a stream-level error (RFC 9113 §5.4.2): send `RST_STREAM`,
    /// notify the application via [`Event::StreamError`], and terminate
    /// the stream. The connection itself stays usable.
    fn stream_error(&mut self, stream_id: u32, code: ErrorCode, msg: &str) {
        if !self.streams.contains(&stream_id) || self.closed {
            return;
        }
        self.pending_frames.push_back(Frame::RstStream {
            stream_id,
            error_code: code,
        });
        self.events.push_back(Event::StreamError {
            stream_id,
            error_code: code,
            message: alloc::string::String::from(msg),
        });
        self.close_stream(stream_id);
    }

    /// Parse a message's `content-length` (RFC 9113 §8.1.2.6). Multiple
    /// fields with identical values are tolerated (RFC 9110 §8.6);
    /// differing or malformed values are a connection error (they are a
    /// request-smuggling vector, CWE-444).
    fn parse_content_length(&mut self, fields: &HeaderList) -> Result<Option<u64>> {
        let mut value: Option<u64> = None;
        for f in fields {
            if f.name.as_str() != "content-length" {
                continue;
            }
            let text = f.value.to_str().map_err(|_| {
                self.protocol_err(ErrorCode::ProtocolError, "invalid content-length")
            })?;
            let n: u64 = text.parse().map_err(|_| {
                self.protocol_err(ErrorCode::ProtocolError, "invalid content-length")
            })?;
            match value {
                None => value = Some(n),
                Some(prev) if prev != n => {
                    return Err(
                        self.protocol_err(ErrorCode::ProtocolError, "conflicting content-length")
                    )
                }
                _ => {}
            }
        }
        Ok(value)
    }

    /// Enforce RFC 9113 §8.1.2.6: a message whose `content-length` does
    /// not match the octets actually received (at stream end) is a
    /// stream error. Also enforces that bodyless messages carry no body
    /// and a zero `content-length`.
    fn verify_content_length(&mut self, stream_id: u32) {
        let bad = match self.streams.get(&stream_id) {
            Some(s) if s.body_expected => match s.content_length {
                Some(expected) => s.recv_body_len != expected,
                None => false,
            },
            Some(s) => s.content_length.is_some_and(|c| c != 0),
            None => false,
        };
        if bad {
            self.stream_error(
                stream_id,
                ErrorCode::ProtocolError,
                "content-length does not match body",
            );
        }
    }

    fn close_stream(&mut self, stream_id: u32) {
        if let Some(s) = self.streams.get_mut(&stream_id) {
            // Release any un-released receive credit on close.
            if s.recv_unreleased > 0 {
                let n = s.recv_unreleased;
                s.recv_unreleased = 0;
                self.conn_recv_window.release(n);
                self.conn_pending_release += n;
            }
            s.state = StreamState::Closed;
            s.recv_ended = true;
            s.send_done = true;
        }
        self.scheduler.remove(stream_id);
        self.scheduled.remove(&stream_id);
        self.send_queue.remove(&stream_id);
        self.pending_priority.remove(&stream_id);
        self.streams.remove(&stream_id);
    }
}

impl Priority {
    /// Extract a priority from a header list's `priority` field, falling
    /// back to the default.
    pub fn parse_headers(fields: &HeaderList) -> Option<Self> {
        for f in fields {
            if f.name.as_str() == "priority" {
                return Priority::parse(f.value.as_bytes());
            }
        }
        None
    }
}

impl<R: Read, W: Write> Connection<R, W> {
    /// Take a buffered client preface if the stream starts with one.
    pub fn peek_preface(reader: &mut BufReader<R>) -> Result<bool> {
        let mut buf = [0u8; 24];
        let mut filled = 0;
        while filled < 24 {
            let b = reader.fill_buf()?;
            if b.is_empty() {
                break;
            }
            let take = core::cmp::min(24 - filled, b.len());
            buf[filled..filled + take].copy_from_slice(&b[..take]);
            filled += take;
            if !frame::CLIENT_PREFACE.starts_with(&buf[..filled]) {
                break;
            }
            reader.consume(take);
        }
        Ok(is_preface(&buf[..filled]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::courierust_hpack::HeaderField;
    use crate::courierust_http::header::{HeaderName, HeaderValue};

    struct OneRead {
        data: Vec<u8>,
        used: bool,
    }

    impl Read for OneRead {
        fn read(&mut self, out: &mut [u8]) -> Result<usize> {
            assert!(!self.used, "batch poll attempted a second transport read");
            self.used = true;
            let n = core::cmp::min(out.len(), self.data.len());
            out[..n].copy_from_slice(&self.data[..n]);
            Ok(n)
        }
    }

    fn hf(name: &str, value: &str) -> HeaderField {
        HeaderField::new(
            HeaderName::from_bytes(name.as_bytes()).unwrap(),
            HeaderValue::from_bytes(value.as_bytes()).unwrap(),
        )
    }

    #[test]
    fn priority_header_parsing() {
        let fields = vec![hf("priority", "u=1, i")];
        assert_eq!(
            Priority::parse_headers(&fields),
            Some(Priority {
                urgency: 1,
                incremental: true
            })
        );
        let none = vec![hf("x-a", "b")];
        assert_eq!(Priority::parse_headers(&none), None);
    }

    #[test]
    fn batch_poll_does_not_read_past_buffered_frames() {
        let mut wire = BytesMut::new();
        Frame::Settings {
            ack: true,
            entries: Vec::new(),
        }
        .encode(&mut wire);
        let reader = OneRead {
            data: wire.into_vec(),
            used: false,
        };
        let writer = crate::courierust_io::VecWriter(Vec::new());
        let mut conn = Connection::new(reader, writer, Config::default());

        assert!(conn.poll_available(64).unwrap());
    }
}
