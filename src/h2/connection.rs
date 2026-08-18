//! Full HTTP/2 connection session: framing, HPACK, flow control,
//! RFC 9218 priority scheduling and the application event queue.
//!
//! The session is generic over [`crate::io::Read`]/[`crate::io::Write`]
//! and owns all per-connection state, so the same code runs over TCP or
//! an external TLS stream. Applications drive it with [`Connection::poll`]
//! (one frame per call) and drain [`Event`]s; outbound requests go
//! through `send_*`.

use crate::bytes::{Bytes, BytesMut};
use crate::error::{Error, ErrorKind, Result};
use crate::h2::error::ErrorCode;
use crate::h2::flow::FlowWindow;
use crate::h2::frame::{self, Frame, FrameHeader};
use crate::h2::priority::{Priority, Scheduler};
use crate::h2::settings::{Setting, Settings};
use crate::h2::stream::{Stream, StreamMap, StreamState};
use crate::hpack::{Decoder, Encoder, HeaderList};
use crate::io::{BufReader, BufWriter, Read, Write};
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
}

/// A partially-received header block (HEADERS + CONTINUATION).
struct PendingHeaders {
    stream_id: u32,
    block: BytesMut,
    end_stream: bool,
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
            streams: StreamMap::new(is_client),
            scheduler: Scheduler::new(quantum),
            scheduled: alloc::collections::BTreeSet::new(),
            send_queue: BTreeMap::new(),
            pending_priority: BTreeMap::new(),
            conn_send_window: FlowWindow::new(conn_window, i64::from(u32::MAX)),
            conn_recv_window: FlowWindow::new(conn_window, i64::from(u32::MAX)),
            conn_pending_release: 0,
            events: VecDeque::new(),
            goaway_sent: false,
            goaway_received: false,
            peer_last_stream: 0,
            closed: false,
        }
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
        if self.closed {
            return Ok(false);
        }
        let had_pending = !self.pending_frames.is_empty();
        self.flush_outbound()?;
        let read_any = match self.read_and_process_one() {
            Ok(r) => r,
            Err(e) if e.kind == ErrorKind::Timeout => false,
            Err(e) => return Err(e),
        };
        self.flush_outbound()?;
        Ok(had_pending || read_any)
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

        let now_closed = {
            let stream = self
                .streams
                .get_mut(&stream_id)
                .ok_or_else(|| Error::protocol("send_headers: unknown stream"))?;
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
        // Both endpoints are done (e.g. a server response whose HEADERS
        // carry END_STREAM): drop the record now so open_count tracks
        // truly-open streams (RFC 9113 §5.1) instead of growing without
        // bound.
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
            .push_back(Chunk { data, end_stream });
        self.maybe_schedule(stream_id);
        Ok(data_len)
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
            s.recv_window = s.recv_window.saturating_add(n);
            s.recv_unreleased = s.recv_unreleased.saturating_sub(n).max(0);
            if s.recv_unreleased >= stream_release_threshold {
                emit_stream = s.recv_unreleased;
                s.recv_unreleased = 0;
            }
        }
        if emit_stream > 0 {
            self.pending_frames.push_back(Frame::WindowUpdate {
                stream_id,
                increment: emit_stream.min(i64::from(u32::MAX)) as u32,
            });
        }
        self.conn_recv_window.release(n);
        self.conn_pending_release += n;
        let conn_threshold = 65535i64;
        if self.conn_pending_release >= conn_threshold {
            let inc = self.conn_pending_release.min(i64::from(u32::MAX)) as u32;
            self.conn_pending_release = 0;
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
            // Send our SETTINGS once (client: right after the preface;
            // server: immediately).
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

    /// Emit DATA frames for scheduled streams, bounded per flush for
    /// fairness.
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
            // `next` popped the stream from the scheduler queue; mark it
            // unscheduled so `maybe_schedule` can re-queue it if it still
            // has data.
            self.scheduled.remove(&sid);
            let can_send = {
                let s = match self.streams.get(&sid) {
                    Some(s) => s,
                    None => {
                        self.scheduler.remove(sid);
                        continue;
                    }
                };
                // Buffered data is always drainable while credit remains,
                // even after `send_done`.
                s.send_window > 0
            };
            if !can_send {
                self.scheduler.remove(sid);
                self.scheduled.remove(&sid);
                continue;
            }
            // Amount we may emit for this stream this round.
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
            let chunk_end;
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
                chunk_end = chunk.end_stream;
            }
            // Pop the front chunk once fully consumed and decide whether
            // the stream ends here.
            let mut end_stream = false;
            if let Some(q) = self.send_queue.get_mut(&sid) {
                let front_empty = q.front().map(|c| c.data.is_empty()).unwrap_or(false);
                if front_empty {
                    let popped = q.pop_front().unwrap();
                    end_stream = popped.end_stream && q.is_empty();
                }
            }
            let _ = chunk_end;
            {
                let s = self.streams.get_mut(&sid).unwrap();
                s.send_window -= payload.len() as i64;
                s.send_buffered = s.send_buffered.saturating_sub(payload.len());
            }
            self.conn_send_window.consume(payload.len() as i64);
            self.pending_frames.push_back(Frame::Data {
                stream_id: sid,
                data: payload,
                end_stream,
            });
            // Advance the local send state. When both endpoints have
            // finished, the stream record is dropped so open_count tracks
            // only live streams (RFC 9113 §5.1).
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
            // Reschedule if the stream still has data and credit.
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
        let mut hdr = [0u8; 9];
        match self.reader.read_exact_into(&mut hdr) {
            Ok(()) => {}
            Err(e) if e.kind == ErrorKind::Timeout || e.kind == ErrorKind::WouldBlock => {
                return Ok(false)
            }
            Err(e) => return Err(e),
        }
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
        let payload = match self.reader.read_exact(header.len as usize) {
            Ok(p) => p,
            Err(e) if e.kind == ErrorKind::Timeout || e.kind == ErrorKind::WouldBlock => {
                return Ok(false)
            }
            Err(e) => return Err(e),
        };
        let frame = Frame::parse(header, &payload, self.local.max_frame_size)?;
        self.process_frame(frame)?;
        Ok(true)
    }

    fn process_frame(&mut self, frame: Frame) -> Result<()> {
        // Header-block reassembly: once a HEADERS/PUSH_PROMISE without
        // END_HEADERS is seen, only CONTINUATION on the same stream may
        // follow (RFC 9113 §6.10).
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
                // RFC 7540 stream priority is deprecated (RFC 9218 §2);
                // we honor PRIORITY_UPDATE / the Priority header instead.
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
                // ENABLE_PUSH is 0 for clients; receiving PUSH_PROMISE is
                // a connection error.
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
            // Stream must not already exist in a non-idle state.
            if self.config.client {
                // Client: a response HEADERS on a stream we never opened.
                return self.conn_error(ErrorCode::ProtocolError, "response on unknown stream");
            }
            // Server: validate monotonic stream id.
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
            self.streams.insert(s);
            self.events.push_back(Event::Headers {
                stream_id: sid,
                headers: fields,
                end_stream: p.end_stream,
                priority,
            });
            return Ok(());
        }

        // Existing stream.
        let stream = self.streams.get_mut(&sid).unwrap();
        if stream.is_closed() {
            // Late frames on closed streams: reset.
            self.pending_frames.push_back(Frame::RstStream {
                stream_id: sid,
                error_code: ErrorCode::StreamClosed,
            });
            return Ok(());
        }
        if stream.headers_delivered {
            // Trailers.
            self.events.push_back(Event::Trailers {
                stream_id: sid,
                headers: fields,
            });
            stream.recv_ended = true;
            stream.state = match stream.state {
                StreamState::Open => StreamState::HalfClosedRemote,
                StreamState::HalfClosedLocal => StreamState::Closed,
                s => s,
            };
            if stream.state == StreamState::Closed {
                self.events
                    .push_back(Event::StreamClosed { stream_id: sid });
                self.close_stream(sid);
            }
            return Ok(());
        }
        // First headers on an existing stream.
        if self.config.client {
            stream.state = match stream.state {
                StreamState::Open => {
                    if p.end_stream {
                        StreamState::HalfClosedRemote
                    } else {
                        StreamState::Open
                    }
                }
                StreamState::HalfClosedLocal => {
                    // We already ended our side; the peer may still send a
                    // response body.
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
        } else {
            // Server receiving additional HEADERS on an existing stream:
            // only trailers allowed, which must end the stream.
            return self.conn_error(
                ErrorCode::ProtocolError,
                "unexpected HEADERS on existing stream",
            );
        }
        if p.end_stream {
            stream.recv_ended = true;
        }
        let priority = self
            .pending_priority
            .remove(&sid)
            .unwrap_or(stream.priority);
        stream.priority = priority;
        stream.headers_delivered = true;
        self.events.push_back(Event::Headers {
            stream_id: sid,
            headers: fields,
            end_stream: p.end_stream,
            priority,
        });
        if stream.state == StreamState::Closed {
            self.events
                .push_back(Event::StreamClosed { stream_id: sid });
            self.close_stream(sid);
        }
        Ok(())
    }

    fn on_data(&mut self, stream_id: u32, data: Bytes, end_stream: bool) -> Result<()> {
        if !self.streams.contains(&stream_id) {
            return self.conn_error(ErrorCode::ProtocolError, "DATA on unknown stream");
        }
        let len = data.len() as i64;
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
            if end_stream {
                s.recv_ended = true;
                s.state = match s.state {
                    StreamState::Open => StreamState::HalfClosedRemote,
                    StreamState::HalfClosedLocal => StreamState::Closed,
                    s => s,
                };
            }
        }
        if self.conn_recv_window.available() < len {
            return self.conn_error(ErrorCode::FlowControlError, "connection window exceeded");
        }
        self.conn_recv_window.consume(len);
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
        // SETTINGS_ENABLE_PUSH: only meaningful from the server side.
        // SETTINGS_NO_RFC7540_PRIORITIES must not change after first frame.
        if self.peer.no_rfc7540_priorities != new_settings.no_rfc7540_priorities
            && self.peer.no_rfc7540_priorities != 0
        {
            return self.conn_error(
                ErrorCode::ProtocolError,
                "SETTINGS_NO_RFC7540_PRIORITIES changed",
            );
        }
        // Apply the HPACK table size the peer allows us to use.
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
        // Reschedule streams whose send window grew.
        let ids: Vec<u32> = self
            .streams
            .iter()
            .filter(|s| s.can_send())
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
                .filter(|s| s.can_send())
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
            if next > i64::from(u32::MAX) {
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
        self.send_goaway(code, msg.as_bytes());
        self.closed = true;
        Err(Error::h2(code.as_u32(), msg.to_string()))
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
            // Only consume if the prefix matches so far; otherwise leave
            // the data for the HTTP/1 layer.
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
    use crate::hpack::HeaderField;
    use crate::http::header::{HeaderName, HeaderValue};

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
}
