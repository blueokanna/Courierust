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
use crate::courierust_h2::settings::{Setting, Settings, SETTINGS_ENABLE_PUSH};
use crate::courierust_h2::stream::{Stream, StreamMap, StreamState};
use crate::courierust_hpack::{Decoder, Encoder, HeaderList};
use crate::courierust_http::header::is_valid_field_value;
use crate::courierust_io::{BufReader, BufWriter, Read, Write};
use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::ToString;
use alloc::vec::Vec;

/// Whether `buf` holds the HTTP/2 client connection preface.
#[inline]
pub fn is_preface(buf: &[u8]) -> bool {
    buf == frame::CLIENT_PREFACE
}

/// Whether an error says "the transport cannot take more right now"
/// rather than "the connection is gone".
///
/// A non-blocking socket reports `WouldBlock`; a blocking one reports
/// whatever its armed timeout produced, which the net adapter normalises
/// to the same thing and a TLS record layer may carry as a timeout. Both
/// are backpressure — a parked frame can be resumed, a discarded one
/// corrupts the stream — so neither is allowed to end the session. A
/// peer that never drains its window is still caught: the drivers fail
/// the request on its deadline and close the connection when the socket
/// stops making progress altogether.
#[inline]
fn is_backpressure(e: &Error) -> bool {
    matches!(e.kind, ErrorKind::WouldBlock | ErrorKind::Timeout)
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

/// The header-list size actually enforced for an advertised
/// `SETTINGS_MAX_HEADER_LIST_SIZE`.
///
/// `0` advertises "no limit", but an unbounded header list is a memory
/// commitment chosen entirely by the peer, so the enforced cap stays
/// finite — and, more importantly, must not be *zero*: the decoder treats
/// its argument as a byte limit, so a configuration that left the
/// default in place could never decode a single header block.
pub(crate) fn header_list_cap(advertised: u32) -> usize {
    const UNLIMITED_CAP: usize = 16 * 1024 * 1024;
    if advertised == 0 {
        UNLIMITED_CAP
    } else {
        advertised as usize
    }
}

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
    /// Encoded bytes the transport has not taken yet.
    ///
    /// A large upload is paced by the peer's flow-control window, so a
    /// socket write legitimately comes back "not now" in the middle of a
    /// body; a frame that is only staged can be resumed, a frame that
    /// was half-written cannot. Everything destined for the wire is
    /// therefore encoded here first and leaves only as the transport
    /// accepts it.
    out: BytesMut,
    /// Set when the last flush was refused, so a connection whose staging
    /// buffer is empty still pushes the bytes an inner layer retained.
    flush_pending: bool,
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

    // Recently closed stream ids (bounded). RFC 9113 §5.1: frames that
    // arrive for a stream we already closed (e.g. DATA that raced our
    // RST_STREAM) are a stream error of type STREAM_CLOSED — not a
    // connection error that would tear down unrelated streams. This ring
    // lets us distinguish those from truly idle/never-opened streams.
    recently_closed: VecDeque<u32>,

    /// The header-list cap actually enforced on inbound header blocks,
    /// derived from our advertised `SETTINGS_MAX_HEADER_LIST_SIZE` (`0`
    /// advertises "no limit", which still needs a bound).
    local_header_cap: usize,

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
        let local_header_cap = header_list_cap(local.max_header_list_size);
        let conn_window = 65535i64;
        Self {
            reader: BufReader::new(reader, 16 * 1024),
            writer: BufWriter::new(writer, 16 * 1024),
            config,
            encoder: Encoder::new(),
            decoder: Decoder::new(local.header_table_size as usize, local_header_cap),
            local_header_cap,
            preface_pending: is_client,
            local,
            peer,
            settings_sent: false,
            out: BytesMut::new(),
            flush_pending: false,
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
            recently_closed: VecDeque::new(),
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

    /// Number of HTTP/2 streams that are not fully closed on this
    /// connection. This is intentionally per-connection so instrumentation
    /// can distinguish multiplexing from opening many parallel sockets.
    #[inline]
    pub fn open_stream_count(&self) -> usize {
        self.streams.open_count()
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

    /// Flush outbound and process up to `max_frames` buffered inbound
    /// frames in one call (bounded so a busy peer cannot starve command
    /// handling). A transport timeout ends the batch, not the connection.
    ///
    /// The returned flag reports *progress*: a frame arrived, or staged
    /// bytes reached the transport. A peer that has stopped draining its
    /// window therefore reads as `Ok(false)` rather than as a failure,
    /// which is what lets a driver keep its idle accounting honest while
    /// an upload waits in the send buffer.
    pub fn poll_available(&mut self, max_frames: usize) -> Result<bool> {
        if self.closed {
            return Ok(false);
        }
        let mut flushed = self.flush_outbound()?;
        let mut read_any = false;
        for _ in 0..max_frames.max(1) {
            match self.read_and_process_one() {
                Ok(true) => read_any = true,
                Ok(false) => break,
                Err(e) if e.kind == ErrorKind::Timeout || e.kind == ErrorKind::WouldBlock => break,
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
        flushed |= self.flush_outbound()?;
        Ok(flushed || read_any)
    }

    /// Best-effort flush of queued control frames (e.g. GOAWAY) even after
    /// the session is marked closed.
    fn flush_final(&mut self) {
        while let Some(f) = self.pending_frames.pop_front() {
            let mut buf = BytesMut::with_capacity(64);
            f.encode(&mut buf);
            self.out.extend_from_slice(&buf);
        }
        let _ = self.drain_out();
    }

    /// Flush pending outbound frames to the transport.
    pub fn flush(&mut self) -> Result<()> {
        self.flush_outbound().map(|_| ())
    }

    /// Send a header block on a stream (request on the client, response
    /// on the server). The stream must already exist (client: via
    /// [`Connection::open_request`]; server: created by inbound HEADERS).
    ///
    /// The block is checked against the outbound half of RFC 9113 §8.2.2
    /// first: an endpoint MUST NOT *generate* connection-specific fields,
    /// and a peer is entitled to reset the stream when it sees one. Failing
    /// here turns "the far end resets my request" into an error at the call
    /// site, with the field named.
    pub fn send_headers(
        &mut self,
        stream_id: u32,
        fields: &HeaderList,
        end_stream: bool,
    ) -> Result<()> {
        for f in fields.iter() {
            let name = f.name.as_str();
            if matches!(
                name,
                "connection" | "keep-alive" | "proxy-connection" | "transfer-encoding" | "upgrade"
            ) {
                return Err(Error::protocol(alloc::format!(
                    "refusing to send connection-specific header `{name}` in HTTP/2 (RFC 9113 §8.2.2)"
                )));
            }
            if name == "te"
                && !f
                    .value
                    .to_str()
                    .unwrap_or("")
                    .eq_ignore_ascii_case("trailers")
            {
                return Err(Error::protocol(
                    "refusing to send a TE header other than `trailers` in HTTP/2 (RFC 9113 §8.2.2)",
                ));
            }
            if !is_valid_field_value(f.value.as_bytes()) {
                return Err(Error::protocol(alloc::format!(
                    "refusing to send field `{name}` with CR, LF or NUL in its value (RFC 9113 §8.2.1)"
                )));
            }
        }
        if self.goaway_sent || self.closed {
            return Err(Error::canceled("connection closing"));
        }
        // Everything that can fail is checked *before* the HPACK encoder
        // runs. Encoding inserts into the dynamic table, so a block that
        // is abandoned afterwards leaves the peer's table one step behind
        // ours and every later block it decodes fails with
        // COMPRESSION_ERROR — the caller would see one failed request and
        // the connection would be dead for everyone.
        if !self.streams.contains(&stream_id) {
            return Err(Error::protocol("send_headers: unknown stream"));
        }
        // RFC 9113 §6.5.2 sizes a field list by its *uncompressed* fields
        // (name + value + 32 bytes each).
        let peer_limit = self.peer.max_header_list_size as usize;
        if peer_limit != 0 {
            let list_size: usize = fields
                .iter()
                .map(|f| f.name.as_str().len() + f.value.len() + 32)
                .sum();
            if list_size > peer_limit {
                return Err(Error::overflow(
                    "header list exceeds peer SETTINGS_MAX_HEADER_LIST_SIZE",
                ));
            }
        }
        let method = fields
            .iter()
            .find(|f| f.name.as_str() == ":method")
            .and_then(|f| f.value.to_str().ok())
            .unwrap_or("");
        let max = self.peer.max_frame_size as usize;
        let mut block = BytesMut::with_capacity(64);
        self.encoder.encode(fields, &mut block);

        let now_closed = {
            let stream = self.stream_mut(stream_id)?;
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
    ///
    /// The block is checked here rather than where it is encoded: by then
    /// the DATA has gone out and the stream is past its last body byte,
    /// so a rejected trailer could only be reported as a reset stream —
    /// the caller gets an error naming the field instead.
    pub fn send_trailers(&mut self, stream_id: u32, fields: &HeaderList) -> Result<()> {
        for f in fields.iter() {
            let name = f.name.as_str();
            if f.name.is_pseudo() {
                return Err(Error::protocol(alloc::format!(
                    "refusing to send pseudo-header `{name}` in trailers (RFC 9113 §8.1)"
                )));
            }
            if !is_valid_field_value(f.value.as_bytes()) {
                return Err(Error::protocol(alloc::format!(
                    "refusing to send trailer `{name}` with CR, LF or NUL in its value (RFC 9113 §8.2.1)"
                )));
            }
        }
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

    /// Encode everything queued into the outbound buffer and push as much
    /// of it to the transport as it will take.
    ///
    /// Returns whether any byte reached the transport, which is what the
    /// drivers use to tell a peer that is making progress from one that
    /// has stopped draining its window. Backpressure is not an error: the
    /// bytes stay staged and the next poll resumes them.
    fn flush_outbound(&mut self) -> Result<bool> {
        if self.closed {
            return Ok(false);
        }
        if self.preface_pending {
            self.out.extend_from_slice(frame::CLIENT_PREFACE);
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
            self.out.extend_from_slice(&buf);
        }
        self.drain_out()
    }

    /// Hand the staged bytes to the transport, keeping whatever it does
    /// not take.
    ///
    /// The staging buffer is emptied either way: a writer that reports
    /// backpressure has already retained the refused tail itself, ahead
    /// of anything staged later, so the byte stream stays ordered and
    /// lossless without this layer tracking a second offset. What it does
    /// track is that a refusal happened — the retry has to keep flushing
    /// a writer that still owes bytes even when nothing new is queued.
    fn drain_out(&mut self) -> Result<bool> {
        if self.out.is_empty() && !self.flush_pending {
            return Ok(false);
        }
        let staged = core::mem::take(&mut self.out);
        let before = self.writer.written();
        let outcome = if staged.is_empty() {
            self.writer.flush()
        } else {
            self.writer
                .write_all(&staged)
                .and_then(|()| self.writer.flush())
        };
        let progress = self.writer.written() > before;
        self.out = staged;
        self.out.clear();
        match outcome {
            Ok(()) => {
                self.flush_pending = false;
                Ok(progress)
            }
            Err(e) if is_backpressure(&e) => {
                self.flush_pending = true;
                Ok(progress)
            }
            Err(e) => Err(e),
        }
    }

    fn queue_settings(&mut self) {
        let mut entries = self.local.to_vec();
        // RFC 9113 §6.5.2: a server MUST NOT send ENABLE_PUSH (only
        // clients use it to disable server push). nghttp2/curl reject a
        // server SETTINGS carrying it.
        if !self.config.client {
            entries.retain(|s| s.id != SETTINGS_ENABLE_PUSH);
        }
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
                    let Some(popped) = q.pop_front() else {
                        continue;
                    };
                    end_stream = popped.end_stream && q.is_empty();
                    if end_stream {
                        trailers = popped.trailers;
                    }
                }
            }
            {
                let Some(s) = self.streams.get_mut(&sid) else {
                    self.scheduler.remove(sid);
                    self.scheduled.remove(&sid);
                    continue;
                };
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
                    padding: 0,
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
                let s = self.streams.get_mut(&sid);
                if let Some(s) = s {
                    if s.state == StreamState::Open {
                        s.state = StreamState::HalfClosedLocal;
                    }
                }
            }

            let Some(stream) = self.streams.get(&sid) else {
                self.scheduler.remove(sid);
                self.scheduled.remove(&sid);
                continue;
            };
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
            let header = FrameHeader {
                len: ((hdr[0] as u32) << 16) | ((hdr[1] as u32) << 8) | (hdr[2] as u32),
                kind: hdr[3],
                flags: hdr[4],
                stream_id: u32::from_be_bytes([hdr[5] & 0x7f, hdr[6], hdr[7], hdr[8]]),
            };
            if header.len > self.local.max_frame_size {
                self.send_goaway(ErrorCode::FrameSizeError, b"frame too large");
                self.closed = true;
                return Err(Error::h2(
                    ErrorCode::FrameSizeError.as_u32(),
                    "received frame exceeds our max frame size",
                ));
            }
            self.frame.payload_len = header.len as usize;
            self.frame.payload.clear();
            self.frame.payload.resize(self.frame.payload_len, 0);
            self.frame.payload_filled = 0;
            self.frame.header = Some(header);
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

        let Some(header) = self.frame.header.take() else {
            return Err(Error::h2(
                ErrorCode::InternalError.as_u32(),
                "frame header missing after a complete read",
            ));
        };
        // RFC 9113 §6.3 and §6.9 scope two malformed frames to the stream
        // rather than the connection: a PRIORITY whose length is not 5
        // (stream error of type FRAME_SIZE_ERROR) and a stream-level
        // WINDOW_UPDATE with a zero increment (stream error of type
        // PROTOCOL_ERROR). `Frame::parse` reports every malformed frame
        // the same way, and the connection-error path below would GOAWAY
        // the whole multiplex — failing every unrelated in-flight request
        // over one bad frame.
        let stream_scoped: Option<(u32, ErrorCode, &'static str)> =
            if header.kind == frame::kind::PRIORITY {
                if header.stream_id == 0 {
                    Some((0, ErrorCode::ProtocolError, "PRIORITY on stream 0"))
                } else if header.len != 5 {
                    Some((
                        header.stream_id,
                        ErrorCode::FrameSizeError,
                        "PRIORITY length != 5",
                    ))
                } else {
                    None
                }
            } else if header.kind == frame::kind::WINDOW_UPDATE
                && header.stream_id != 0
                && header.len == 4
            {
                let p = self.frame.payload.as_slice();
                let inc = u32::from_be_bytes([p[0] & 0x7f, p[1], p[2], p[3]]);
                if inc == 0 {
                    Some((
                        header.stream_id,
                        ErrorCode::ProtocolError,
                        "WINDOW_UPDATE increment 0 on a stream",
                    ))
                } else {
                    None
                }
            } else {
                None
            };
        self.frame.header = None;
        self.frame.hdr_len = 0;
        self.frame.payload_len = 0;
        self.frame.payload_filled = 0;
        if let Some((sid, code, msg)) = stream_scoped {
            if sid == 0 {
                return self.conn_error(code, msg).map(|_| false);
            }
            self.stream_error(sid, code, msg);
            return Ok(true);
        }
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
                    let pending = self.pending_headers.as_mut().ok_or_else(|| {
                        Error::h2(
                            ErrorCode::InternalError.as_u32(),
                            "CONTINUATION without a header block",
                        )
                    })?;
                    if pending.stream_id != stream_id {
                        return self.conn_error(
                            ErrorCode::ProtocolError,
                            "CONTINUATION on different stream",
                        );
                    }
                    if pending.block.len() + block.len() > self.local_header_cap {
                        return self.conn_error(
                            ErrorCode::CompressionError,
                            "header block exceeds advertised limit",
                        );
                    }
                    pending.block.extend_from_slice(block.as_slice());
                    if end_headers {
                        let p = self.pending_headers.take().ok_or_else(|| {
                            Error::h2(
                                ErrorCode::InternalError.as_u32(),
                                "CONTINUATION lost its header block",
                            )
                        })?;
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
                padding,
            } => self.on_data(stream_id, data, end_stream, padding),
            Frame::RstStream {
                stream_id,
                error_code,
            } => {
                if !self.streams.contains(&stream_id) {
                    // RFC 9113 §5.1: RST_STREAM on an idle stream (one
                    // that was never opened) is a PROTOCOL_ERROR;
                    // RST_STREAM for a stream that has already closed is
                    // a normal race and MUST be ignored.
                    //
                    // The `last_peer_id` test only sees *peer-initiated*
                    // streams, which on a client connection is none of
                    // them — so a server that resets a stream we already
                    // finished (§8.1: it may send RST_STREAM(NO_ERROR)
                    // to tell us to stop sending) used to look like an
                    // idle-stream error and killed the whole connection.
                    // `recently_closed` is the record that knows better.
                    if self.recently_closed.iter().any(|&c| c == stream_id) {
                        return Ok(());
                    }
                    if stream_id > self.streams.last_peer_id() {
                        return self
                            .conn_error(ErrorCode::ProtocolError, "RST_STREAM on idle stream");
                    }
                    return Ok(());
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
                } else if self.pending_priority.len() < 1024 {
                    self.pending_priority
                        .insert(prioritized_stream_id, priority);
                } else {
                    // The cap is a memory guard, not a policy: once the hint
                    // table is full a *new* priority is worth more than a
                    // stale one, so the table is reset rather than the update
                    // dropped.
                    self.pending_priority.clear();
                    self.pending_priority
                        .insert(prioritized_stream_id, priority);
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
            if !self.validate_header_block(sid, &fields, !self.config.client, false)? {
                return Ok(());
            }

            if self.config.client {
                if self.recently_closed.iter().any(|&c| c == sid) {
                    self.pending_frames.push_back(Frame::RstStream {
                        stream_id: sid,
                        error_code: ErrorCode::StreamClosed,
                    });
                    return Ok(());
                }
                return self.conn_error(ErrorCode::ProtocolError, "response on unknown stream");
            }
            if self.goaway_sent && sid > self.streams.last_peer_id() {
                // RFC 9113 §6.8/§8.7: our GOAWAY promised that streams
                // above the id it carried were not processed, which is what
                // lets the client safely retry them on another connection.
                // Running one anyway would execute a non-idempotent request
                // twice.
                self.stream_error(sid, ErrorCode::RefusedStream, "stream opened after GOAWAY");
                return Ok(());
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
            let s = self.stream_ref(sid)?;
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
            if !self.validate_header_block(sid, &fields, false, true)? {
                return Ok(());
            }
            self.verify_content_length(sid);
            if !self.streams.contains(&sid) {
                return Ok(());
            }
            self.events.push_back(Event::Trailers {
                stream_id: sid,
                headers: fields,
            });
            let closed = {
                let s = self.stream_mut(sid)?;
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
        if !self.validate_header_block(sid, &fields, false, false)? {
            return Ok(());
        }
        let cl = self.parse_content_length(&fields)?;
        let status = fields
            .iter()
            .find(|f| f.name.as_str() == ":status")
            .and_then(|f| f.value.to_str().ok())
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(200);
        if (100..=199).contains(&status) && self.config.client {
            if p.end_stream {
                self.pending_frames.push_back(Frame::RstStream {
                    stream_id: sid,
                    error_code: ErrorCode::Cancel,
                });
                self.events.push_back(Event::StreamError {
                    stream_id: sid,
                    error_code: ErrorCode::Cancel,
                    message: alloc::string::String::from(
                        "peer sent only an informational response",
                    ),
                });
                self.close_stream(sid);
                return Ok(());
            }
            return Ok(());
        }
        let status_expects_body = !(100..=199).contains(&status) && status != 204 && status != 304;
        // Pop the pending priority before the state block: the stream is
        // borrowed mutably inside it. The removal used to sit after the
        // state check, whose only exit closes the connection anyway.
        let pending_priority = self.pending_priority.remove(&sid);
        let priority;
        {
            let stream = self.stream_mut(sid)?;
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
            priority = pending_priority.unwrap_or(stream.priority);
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

    /// Validate an inbound header block against RFC 9113 §8.1:
    ///
    /// * Pseudo-headers must precede all regular fields, and pseudo-header
    ///   fields must not be repeated.
    /// * Requests require `:method`, `:scheme` and `:path` (or, for
    ///   `CONNECT`, exactly `:authority`); responses require exactly one
    ///   three-digit `:status`.
    /// * No unknown pseudo-headers, and no cross-contamination of
    ///   request/response pseudo-headers. `:protocol` (RFC 8441 extended
    ///   CONNECT) is unknown to this stack, and resetting the stream is
    ///   the outcome RFC 8441 §3 defines for a peer that never sent
    ///   `SETTINGS_ENABLE_CONNECT_PROTOCOL` — which this stack never sends.
    /// * Connection-specific fields (RFC 9113 §8.2.2) must be absent; `te`
    ///   may only carry `trailers`. This is the rule that makes a
    ///   WebSocket `Upgrade` attempt over HTTP/2 fail as a rejected stream
    ///   instead of being handed to the handler as an ordinary request.
    /// * Trailers must not contain pseudo-headers or framing fields.
    ///
    /// A violation resets **that stream** (`Ok(false)`, `PROTOCOL_ERROR`)
    /// and leaves the connection and every other stream usable — RFC 9113
    /// §8.1.1 makes a malformed *message* a stream error for exactly that
    /// reason. `Err` is reserved for conditions that would desynchronise
    /// the connection, and the caller must stop processing the block when
    /// this returns `Ok(false)`.
    fn validate_header_block(
        &mut self,
        stream_id: u32,
        fields: &HeaderList,
        is_request: bool,
        is_trailer: bool,
    ) -> Result<bool> {
        let mut saw_regular = false;
        let mut method: Option<&str> = None;
        let mut has_scheme = false;
        let mut path: Option<&str> = None;
        let mut has_authority = false;
        let mut has_status = false;
        let mut saw_method = false;
        let mut saw_scheme = false;
        let mut saw_path = false;
        let mut saw_authority = false;

        for f in fields.iter() {
            // RFC 9113 §8.2.1: NUL, LF or CR anywhere in a field value
            // makes the message malformed — a stream error under
            // §8.1.1, never a connection error. A value that is invalid
            // only to a *byte class* (a control character such as 0x01)
            // is caught by the same check.
            if !is_valid_field_value(f.value.as_bytes()) {
                self.reject_malformed(
                    stream_id,
                    "field value contains a control character (RFC 9113 §8.2.1)",
                );
                return Ok(false);
            }
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
                    self.reject_malformed(
                        stream_id,
                        &alloc::format!(
                            "connection-specific header `{n}` in HTTP/2 (RFC 9113 §8.2.2); a WebSocket upgrade belongs on HTTP/1.1"
                        ),
                    );
                    return Ok(false);
                }
                if n == "te" {
                    let v = f.value.to_str().unwrap_or("");
                    if !v.eq_ignore_ascii_case("trailers") {
                        self.reject_malformed(
                            stream_id,
                            "TE header must be `trailers` in HTTP/2 (RFC 9113 §8.2.2)",
                        );
                        return Ok(false);
                    }
                }
                if is_trailer && matches!(n, "content-length" | "host" | "trailer" | "te") {
                    self.reject_malformed(stream_id, "framing field in trailers");
                    return Ok(false);
                }
                continue;
            }
            if saw_regular {
                self.reject_malformed(
                    stream_id,
                    "pseudo-header after regular field (RFC 9113 §8.3)",
                );
                return Ok(false);
            }
            if is_trailer {
                self.reject_malformed(stream_id, "pseudo-header in trailers (RFC 9113 §8.1)");
                return Ok(false);
            }
            match f.name.as_str() {
                ":method" => {
                    if !is_request {
                        self.reject_malformed(stream_id, ":method in response");
                        return Ok(false);
                    }
                    if saw_method {
                        self.reject_malformed(stream_id, "duplicate :method (RFC 9113 §8.3)");
                        return Ok(false);
                    }
                    saw_method = true;
                    method = f.value.to_str().ok();
                }
                ":scheme" => {
                    if !is_request {
                        self.reject_malformed(stream_id, ":scheme in response");
                        return Ok(false);
                    }
                    if saw_scheme {
                        self.reject_malformed(stream_id, "duplicate :scheme (RFC 9113 §8.3)");
                        return Ok(false);
                    }
                    saw_scheme = true;
                    has_scheme = true;
                }
                ":path" => {
                    if !is_request {
                        self.reject_malformed(stream_id, ":path in response");
                        return Ok(false);
                    }
                    if saw_path {
                        self.reject_malformed(stream_id, "duplicate :path (RFC 9113 §8.3)");
                        return Ok(false);
                    }
                    saw_path = true;
                    path = f.value.to_str().ok();
                }
                ":authority" => {
                    if !is_request {
                        self.reject_malformed(stream_id, ":authority in response");
                        return Ok(false);
                    }
                    if saw_authority {
                        self.reject_malformed(stream_id, "duplicate :authority (RFC 9113 §8.3)");
                        return Ok(false);
                    }
                    saw_authority = true;
                    has_authority = true;
                }
                ":status" => {
                    if is_request {
                        self.reject_malformed(stream_id, ":status in request");
                        return Ok(false);
                    }
                    if has_status {
                        self.reject_malformed(stream_id, "duplicate :status (RFC 9113 §8.3)");
                        return Ok(false);
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
                        self.reject_malformed(stream_id, "invalid :status value");
                        return Ok(false);
                    }
                }
                ":protocol" => {
                    self.reject_malformed(
                        stream_id,
                        "extended CONNECT (:protocol) is not implemented; WebSocket over HTTP/2 (RFC 8441) is rejected and must use HTTP/1.1",
                    );
                    return Ok(false);
                }
                _ => {
                    self.reject_malformed(stream_id, "unknown pseudo-header (RFC 9113 §8.3)");
                    return Ok(false);
                }
            }
        }
        if is_trailer {
            return Ok(true);
        }
        if is_request {
            let is_connect = method == Some("CONNECT");
            if is_connect {
                if has_scheme || path.is_some() {
                    self.reject_malformed(
                        stream_id,
                        "CONNECT must not carry :scheme or :path (RFC 9113 §8.5)",
                    );
                    return Ok(false);
                }
                if !has_authority {
                    self.reject_malformed(stream_id, "CONNECT requires :authority (RFC 9113 §8.5)");
                    return Ok(false);
                }
            } else {
                if method.is_none() {
                    self.reject_malformed(stream_id, "request missing :method (RFC 9113 §8.3.1)");
                    return Ok(false);
                }
                if !has_scheme {
                    self.reject_malformed(stream_id, "request missing :scheme (RFC 9113 §8.3.1)");
                    return Ok(false);
                }
                match path {
                    None => {
                        self.reject_malformed(stream_id, "request missing :path (RFC 9113 §8.3.1)");
                        return Ok(false);
                    }
                    Some("") => {
                        self.reject_malformed(stream_id, "empty :path (RFC 9113 §8.3.1)");
                        return Ok(false);
                    }
                    _ => {}
                }
            }
        } else if !has_status {
            self.reject_malformed(stream_id, "response missing :status (RFC 9113 §8.3.2)");
            return Ok(false);
        }
        Ok(true)
    }

    fn on_data(
        &mut self,
        stream_id: u32,
        data: Bytes,
        end_stream: bool,
        padding: usize,
    ) -> Result<()> {
        if !self.streams.contains(&stream_id) {
            if self.recently_closed.iter().any(|&c| c == stream_id) {
                self.pending_frames.push_back(Frame::RstStream {
                    stream_id,
                    error_code: ErrorCode::StreamClosed,
                });
                return Ok(());
            }
            return self.conn_error(ErrorCode::ProtocolError, "DATA on unknown stream");
        }
        // RFC 9113 §6.1: padding is flow controlled too, so the window
        // is spent on `data.len() + padding` while only `data` is body.
        let len = (data.len() + padding) as i64;
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
            let s = self.stream_mut(stream_id)?;
            if !s.can_recv() {
                // The peer sent DATA after its own END_STREAM (or after we
                // reset it): a stream error, and the stream really has to
                // close — leaving the record alive would let the
                // application queue a response on a stream we just reset.
                self.stream_error(
                    stream_id,
                    ErrorCode::StreamClosed,
                    "DATA after the stream was closed",
                );
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
        // RFC 9113 §6.5.2: a server MUST NOT *explicitly* set
        // SETTINGS_ENABLE_PUSH to 1 — "if a server does include a value, it
        // MUST be 0" — and a client MUST treat receipt of one as a
        // connection error of type PROTOCOL_ERROR. The peer's *effective*
        // value is 1 either way (that is the protocol default, and the
        // merged settings start there), so the check has to look at what
        // the frame actually carried.
        if self.config.client
            && entries
                .iter()
                .any(|s| s.id == SETTINGS_ENABLE_PUSH && s.value == 1)
        {
            return self.conn_error(
                ErrorCode::ProtocolError,
                "server sent SETTINGS_ENABLE_PUSH=1",
            );
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
        let delta = new_settings.initial_window_size as i64 - self.peer.initial_window_size as i64;
        if delta != 0 {
            let ids: Vec<u32> = self.streams.iter().map(|s| s.id).collect();
            // RFC 9113 §6.5.2: a change that would push *any* window past
            // the maximum is a connection error of type FLOW_CONTROL_ERROR.
            // The old `next < i64::MIN` test could never be true (the
            // window never goes negative by more than its own value), so a
            // peer could first raise a stream window to the 2^31-1 limit
            // with WINDOW_UPDATE and then raise INITIAL_WINDOW_SIZE to add
            // it a second time, after which every send exceeds what the
            // peer thinks our window is.
            for id in &ids {
                let window = self.streams.get(id).map(|s| s.send_window).unwrap_or(0);
                if window.saturating_add(delta) > MAX_FLOW_WINDOW {
                    return self.conn_error(
                        ErrorCode::FlowControlError,
                        "SETTINGS_INITIAL_WINDOW_SIZE overflows a stream window",
                    );
                }
            }
            for id in ids {
                let s = self.stream_mut(id)?;
                s.send_window = s.send_window.saturating_add(delta);
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
                None => {
                    // RFC 9113 §5.1: WINDOW_UPDATE on an *idle* stream is a
                    // connection error, on a closed one it is ignored. A
                    // stream that was allocated (ours) or accepted (the
                    // peer's) already existed, so only an id beyond that
                    // range can be idle; the recently-closed ring covers
                    // the rest.
                    let ever_opened = if self.config.client {
                        stream_id < self.streams.peek_client_id()
                    } else {
                        stream_id <= self.streams.last_peer_id()
                    };
                    if ever_opened || self.recently_closed.iter().any(|&c| c == stream_id) {
                        return Ok(());
                    }
                    return self
                        .conn_error(ErrorCode::ProtocolError, "WINDOW_UPDATE on an idle stream");
                }
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

    /// The record of a live stream. Every path that reaches these two
    /// helpers inserts the stream first, so a missing record is an internal
    /// fault: it is reported, never unwrapped — a driver that panics on its
    /// own bookkeeping takes the whole connection (and every multiplexed
    /// request on it) down with it.
    fn stream_ref(&self, id: u32) -> Result<&Stream> {
        self.streams.get(&id).ok_or_else(|| {
            Error::h2(
                ErrorCode::InternalError.as_u32(),
                "stream table lost a live stream",
            )
        })
    }

    /// Mutable counterpart of [`Self::stream_ref`].
    fn stream_mut(&mut self, id: u32) -> Result<&mut Stream> {
        self.streams.get_mut(&id).ok_or_else(|| {
            Error::h2(
                ErrorCode::InternalError.as_u32(),
                "stream table lost a live stream",
            )
        })
    }

    /// Surface a stream-level error (RFC 9113 §5.4.2): send `RST_STREAM`,
    /// notify the application via [`Event::StreamError`], and terminate
    /// the stream. The connection itself stays usable.
    ///
    /// The stream does not have to exist yet. The malformed-message paths
    /// (RFC 9113 §8.1.1) run *before* a request is registered, and
    /// resetting a not-yet-registered stream is exactly the behaviour the
    /// RFC prescribes — including RFC 8441 §3, where a peer that does not
    /// support extended CONNECT resets the stream rather than the
    /// connection.
    fn stream_error(&mut self, stream_id: u32, code: ErrorCode, msg: &str) {
        if self.closed {
            return;
        }
        if self.streams.contains(&stream_id) {
            self.events.push_back(Event::StreamError {
                stream_id,
                error_code: code,
                message: alloc::string::String::from(msg),
            });
        }
        self.pending_frames.push_back(Frame::RstStream {
            stream_id,
            error_code: code,
        });
        self.close_stream(stream_id);
    }

    /// Reject one stream for a malformed message (RFC 9113 §8.1.1) and
    /// keep the connection — and every other stream on it — usable.
    ///
    /// §8.1.1 makes a malformed *message* a stream error precisely so one
    /// bad field block cannot fail the whole multiplex; §5.4 permits the
    /// stricter reading, and this stack takes it where a desynchronised
    /// decoder is the likelier explanation (HPACK errors are
    /// `COMPRESSION_ERROR` connection errors, and conflicting framing
    /// fields stay connection errors as a request-smuggling guard).
    fn reject_malformed(&mut self, stream_id: u32, msg: &str) {
        if !self.config.client {
            self.streams.accept_peer_id(stream_id);
        }
        self.stream_error(stream_id, ErrorCode::ProtocolError, msg);
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
    /// stream error. Also enforces that bodyless messages carry no body.
    fn verify_content_length(&mut self, stream_id: u32) {
        let bad = match self.streams.get(&stream_id) {
            Some(s) if s.body_expected => match s.content_length {
                Some(expected) => s.recv_body_len != expected,
                None => false,
            },
            // A response that is defined to have no content MAY carry a
            // non-zero `content-length` (RFC 9113 §8.1.1, RFC 9110 §8.6
            // for HEAD): every server answers HEAD with the entity length
            // and no DATA. Only DATA actually received is a mismatch.
            Some(s) => s.recv_body_len != 0,
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
        let conn_threshold = 32 * 1024i64;
        if self.conn_pending_release >= conn_threshold {
            let inc = self.conn_pending_release.min(i64::from(u32::MAX)) as u32;
            self.conn_pending_release = 0;
            self.pending_frames.push_back(Frame::WindowUpdate {
                stream_id: 0,
                increment: inc,
            });
        }
        self.scheduler.remove(stream_id);
        self.scheduled.remove(&stream_id);
        self.send_queue.remove(&stream_id);
        self.pending_priority.remove(&stream_id);
        self.streams.remove(&stream_id);
        self.recently_closed.push_back(stream_id);
        const CLOSED_TRACK: usize = 2048;
        if self.recently_closed.len() > CLOSED_TRACK {
            self.recently_closed.pop_front();
        }
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
    use alloc::rc::Rc;
    use core::cell::Cell;

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

    fn hf(name: &'static str, value: &str) -> HeaderField {
        HeaderField::new(
            HeaderName::from_lowercase(name),
            HeaderValue::from_bytes(value.as_bytes()).unwrap(),
        )
    }

    /// A reader that behaves like a socket with nothing to say yet.
    struct Silent;

    impl Read for Silent {
        fn read(&mut self, _out: &mut [u8]) -> Result<usize> {
            Err(Error::new(ErrorKind::WouldBlock))
        }
    }

    /// A transport that refuses every write while its budget of calls is
    /// exhausted — the knob the test flips — and otherwise takes
    /// `max_chunk` bytes at a time.
    struct Refusing {
        out: Vec<u8>,
        calls: Rc<Cell<usize>>,
        refuse_calls: Rc<Cell<usize>>,
        max_chunk: usize,
    }

    impl Refusing {
        fn unblocked() -> Self {
            Self {
                out: Vec::new(),
                calls: Rc::new(Cell::new(0)),
                refuse_calls: Rc::new(Cell::new(0)),
                max_chunk: usize::MAX,
            }
        }
    }

    impl Write for Refusing {
        fn write(&mut self, buf: &[u8]) -> Result<usize> {
            self.calls.set(self.calls.get() + 1);
            if self.calls.get() <= self.refuse_calls.get() {
                return Err(Error::new(ErrorKind::WouldBlock));
            }
            let n = buf.len().min(self.max_chunk);
            self.out.extend_from_slice(&buf[..n]);
            Ok(n)
        }

        fn flush(&mut self) -> Result<()> {
            Ok(())
        }
    }

    /// The same exchange on both transports: connection setup, then a
    /// request whose body needs several frames.
    fn small_upload<W: Write>(conn: &mut Connection<Silent, W>) {
        let sid = conn.open_request(Priority::default()).unwrap();
        let fields = vec![
            hf(":method", "POST"),
            hf(":scheme", "http"),
            hf(":path", "/upload"),
            hf(":authority", "localhost"),
        ];
        conn.send_headers(sid, &fields, false).unwrap();
        conn.send_data(sid, Bytes::from(vec![0x77_u8; 4096]), true)
            .unwrap();
    }

    /// A full send buffer is backpressure, not a dead connection. With
    /// the window closed the driver keeps polling and the bytes stay put;
    /// once the peer drains, the upload resumes where it stopped, so the
    /// stream the peer sees matches the one it would have seen without
    /// the pause, exactly.
    #[test]
    fn backpressure_is_resumed_without_touching_the_byte_stream() {
        let mut reference = Connection::new(Silent, Refusing::unblocked(), Config::default());
        small_upload(&mut reference);
        while reference.poll_available(64).unwrap() {}
        let want = reference.writer.get_ref().out.clone();
        assert!(want.len() > 4096, "the body is on the wire");

        let blocked = Rc::new(Cell::new(usize::MAX));
        let mut stalled = Connection::new(
            Silent,
            Refusing {
                out: Vec::new(),
                calls: Rc::new(Cell::new(0)),
                refuse_calls: Rc::clone(&blocked),
                max_chunk: 512,
            },
            Config::default(),
        );
        small_upload(&mut stalled);
        for _ in 0..4 {
            // Refusals are absorbed: no error, no closed session, and no
            // progress to report — the driver's idle logic stays honest.
            assert!(!stalled
                .poll_available(64)
                .expect("backpressure is not a connection error"));
        }
        assert!(!stalled.is_closed());
        assert!(
            stalled.writer.get_ref().out.is_empty(),
            "nothing reached the transport"
        );

        // The peer drains; the same session picks up from its tail.
        blocked.set(0);
        for _ in 0..64 {
            if stalled.writer.get_ref().out.len() == want.len() {
                break;
            }
            stalled.poll_available(64).unwrap();
        }
        assert_eq!(
            stalled.writer.get_ref().out,
            want,
            "the stream is byte-exact after the pause"
        );
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

    /// RFC 9113 §8.2.1: a field value carrying NUL, LF or CR is malformed
    /// for HTTP/2 too, even though no frame can be split by one. The
    /// value never leaves this stack, so the check has to happen on the
    /// way out; `HeaderValue`'s `From<&str>` skips validation, which is
    /// exactly how such a value gets this far.
    #[test]
    fn send_headers_refuses_control_characters_in_values() {
        let reader = OneRead {
            data: Vec::new(),
            used: false,
        };
        let writer = crate::courierust_io::VecWriter(Vec::new());
        let mut conn = Connection::new(reader, writer, Config::default());
        let stream = conn.open_request(Priority::default()).unwrap();
        let mut fields = request_prefix();
        fields.push(HeaderField::new(
            HeaderName::from_lowercase("x-injected"),
            HeaderValue::from("ok\r\nx-evil: 1"),
        ));
        let err = conn
            .send_headers(stream, &fields, true)
            .expect_err("a value with CR/LF must not be sent");
        assert!(
            err.to_string().contains("x-injected"),
            "the error must name the offending field: {err}"
        );
    }

    /// The trailer block is written after the last body byte, so a
    /// malformed one is checked where it is queued — otherwise the only
    /// way to report it would be a reset stream.
    #[test]
    fn send_trailers_refuses_malformed_fields() {
        let reader = OneRead {
            data: Vec::new(),
            used: false,
        };
        let writer = crate::courierust_io::VecWriter(Vec::new());
        let mut conn = Connection::new(reader, writer, Config::default());
        let stream = conn.open_request(Priority::default()).unwrap();
        conn.send_headers(stream, &request_prefix(), false).unwrap();

        // RFC 9113 §8.1: trailers must not carry pseudo-headers.
        let pseudo = vec![hf(":status", "200")];
        assert!(
            conn.send_trailers(stream, &pseudo).is_err(),
            "a pseudo-header in trailers must be refused"
        );

        let injected = vec![HeaderField::new(
            HeaderName::from_lowercase("x-trailer"),
            HeaderValue::from("done\r\n"),
        )];
        assert!(
            conn.send_trailers(stream, &injected).is_err(),
            "a trailer value with CR/LF must be refused"
        );

        // A well-formed block still goes through.
        let ok = vec![hf("x-trailer", "done")];
        assert!(conn.send_trailers(stream, &ok).is_ok());
    }

    fn request_prefix() -> Vec<HeaderField> {
        vec![
            hf(":method", "GET"),
            hf(":scheme", "http"),
            hf(":path", "/"),
            hf(":authority", "example.test"),
        ]
    }

    /// RFC 9113 §8.2.2 forbids *generating* connection-specific fields.
    /// The outbound check turns "the peer will reset this stream" into a
    /// local error that names the field — this is the mirror image of the
    /// inbound rule, and it is what keeps a WebSocket-shaped request from
    /// leaving this stack over HTTP/2.
    #[test]
    fn send_headers_refuses_connection_specific_fields() {
        let reader = OneRead {
            data: Vec::new(),
            used: false,
        };
        let writer = crate::courierust_io::VecWriter(Vec::new());
        let mut conn = Connection::new(reader, writer, Config::default());
        let stream = conn.open_request(Priority::default()).unwrap();

        let base = vec![
            hf(":method", "GET"),
            hf(":scheme", "http"),
            hf(":path", "/"),
            hf(":authority", "example.test"),
        ];
        let mut with_upgrade = base.clone();
        with_upgrade.push(hf("upgrade", "websocket"));
        let err = conn
            .send_headers(stream, &with_upgrade, true)
            .expect_err("a WebSocket upgrade must not be sent over HTTP/2");
        assert!(
            err.to_string().contains("upgrade"),
            "the error must name the offending field: {err}"
        );

        let mut with_bad_te = base.clone();
        with_bad_te.push(hf("te", "gzip"));
        assert!(
            conn.send_headers(stream, &with_bad_te, true).is_err(),
            "TE must be `trailers` or absent"
        );

        // `te: trailers` and ordinary fields are legal and still go out.
        let mut legal = base;
        legal.push(hf("te", "trailers"));
        assert!(conn.send_headers(stream, &legal, true).is_ok());
    }
}
