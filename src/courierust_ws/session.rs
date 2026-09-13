//! The WebSocket session state machine.
//!
//! Implements RFC 6455 §5–§7 on any `Read`/`Write` transport:
//! fragmentation and reassembly, control frames interleaved at fragment
//! boundaries, the closing handshake, masking in the correct direction,
//! and `permessage-deflate` when negotiated.
//!
//! [`Session::poll_message`] never blocks on a partial frame and never
//! loses one — header bytes, payload bytes and a partial UTF-8 sequence
//! all survive across calls — so the same code drives `read_message` on a
//! worker thread and `poll_message` on an event-loop reactor, where an
//! idle connection costs a buffer instead of a thread.
//!
//! Every buffer is bounded by configuration, not by the peer: `max_frame`,
//! `max_message` (after inflating), a ≤32 KiB sliding window, and
//! masking in fixed 16 KiB windows.

use crate::courierust_bytes::Bytes;
use crate::courierust_deflate::Inflater;
use crate::courierust_error::{Error, ErrorKind, Result};
use crate::courierust_io::{BufReader, Read};
use crate::courierust_ws::frame::{self, close, FrameHeader, Mask, OpCode, MAX_HEADER_LEN};
use crate::courierust_ws::handshake::CompressionParams;
use crate::courierust_ws::utf8::Utf8Validator;
use crate::courierust_ws::writer::FrameWriter;
use alloc::string::String;
use alloc::vec::Vec;

/// Payload remainder from which a session reads directly into the
/// message buffer instead of through the internal read buffer.
///
/// Below this the copy through the buffer is cheaper than the extra
/// bookkeeping (and small messages are usually already buffered anyway);
/// above it a frame is filled straight at its destination.
const DIRECT_READ_MIN: usize = 8 * 1024;

/// Which end of the connection this session is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Client: outgoing frames are masked, incoming frames must not be.
    Client,
    /// Server: outgoing frames are unmasked, incoming frames must be.
    Server,
}

/// How outbound masking keys are produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MaskSource {
    /// Never mask: the only legal choice for a server (§5.1).
    #[default]
    None,
    /// A fixed key. Deterministic: for tests and fuzzing, and for
    /// `no_std` callers that inject their own entropy.
    Fixed([u8; 4]),
    /// Platform CSPRNG, used to seed a ChaCha20 stream per session. The
    /// default for clients; RFC 6455 §5.3 requires the key to be
    /// *unpredictable*, which keeps an intermediary's caches from being
    /// poisoned by a chosen mask.
    #[cfg(feature = "std")]
    Random,
}

/// Session limits and policies.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Which end we are.
    pub role: Role,
    /// Largest accepted single frame payload.
    pub max_frame: usize,
    /// Largest accepted (decompressed) message.
    pub max_message: usize,
    /// Largest number of fragments in one message; 0 disables the check.
    /// Bounds the CPU a peer can spend on headers instead of data.
    pub max_fragments: u32,
    /// Negotiated compression, or `None`.
    pub compression: Option<CompressionParams>,
    /// Answer Pings automatically (RFC 6455 §5.5.2 requires a Pong).
    pub auto_pong: bool,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            role: Role::Server,
            max_frame: 16 * 1024 * 1024,
            max_message: 16 * 1024 * 1024,
            max_fragments: 0,
            compression: None,
            auto_pong: true,
        }
    }
}

/// What a session produced for the application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A complete UTF-8 text message.
    Text(String),
    /// A complete binary message.
    Binary(Bytes),
    /// A Ping (already answered when `auto_pong` is on).
    Ping(Bytes),
    /// A Pong.
    Pong(Bytes),
    /// The peer's closing frame (our reply is already sent).
    Close(Option<close::CloseFrame>),
}

/// Counters for operators and benchmarks. All updates are plain
/// increments on plain fields: the session is owned by one thread, so
/// there is no atomic in the hot path.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Stats {
    /// Frames received.
    pub frames_read: u64,
    /// Frames sent.
    pub frames_written: u64,
    /// Complete messages received.
    pub messages_read: u64,
    /// Complete messages sent.
    pub messages_written: u64,
    /// Payload bytes received.
    pub bytes_read: u64,
    /// Payload (and header) bytes sent.
    pub bytes_written: u64,
    /// Pings received (each one is answered unless `auto_pong` is off).
    pub pings_received: u64,
    /// Pings sent.
    pub pings_sent: u64,
    /// Pongs received.
    pub pongs_received: u64,
    /// Pongs sent.
    pub pongs_sent: u64,
    /// Fragments beyond the first for every message.
    pub fragments_read: u64,
    /// Messages received that arrived compressed.
    pub compressed_read: u64,
    /// Messages sent compressed.
    pub compressed_written: u64,
    /// Bytes saved by compressing outgoing messages (compressed size
    /// subtracted from the plaintext size).
    pub bytes_saved_written: i64,
    /// Close frames exchanged (either direction).
    pub closes: u64,
    /// Protocol violations detected (each one ends the connection).
    pub violations: u64,
}

impl Stats {
    /// A fresh, zeroed counter set.
    pub fn new() -> Self {
        Self::default()
    }
}

/// Reader state: what the next call must consume.
enum Phase {
    /// Collecting a frame header; `filled` bytes are already in `head`.
    Header { filled: usize },
    /// Reading a payload; `got` bytes are already buffered.
    Payload { header: FrameHeader, got: usize },
    /// Terminal: the closing handshake completed (or a fatal protocol
    /// error was reported).
    Finished,
}

/// One WebSocket connection.
pub struct Session<R: Read, S: frame::FrameSink> {
    reader: BufReader<R>,
    writer: FrameWriter<S>,
    cfg: SessionConfig,

    // ---- read state -------------------------------------------------
    phase: Phase,
    head: [u8; MAX_HEADER_LEN],
    /// Message assembly buffer (raw payload bytes as they arrive; a
    /// compressed message holds the *compressed* bytes until FIN).
    msg: Vec<u8>,
    /// Control-frame payload buffer (125 bytes max; capacity is reused).
    ctl: Vec<u8>,
    /// Opcode of the message currently being assembled.
    msg_opcode: Option<OpCode>,
    /// Whether the message in `msg` was sent compressed (RSV1).
    msg_compressed: bool,
    /// Fragments already accepted for this message.
    fragments: u32,
    utf8: Utf8Validator,

    // ---- receive-side compression -----------------------------------
    inflater: Option<Inflater>,
    /// Reused buffer for decompressed output.
    dec_buf: Vec<u8>,

    // ---- close state ------------------------------------------------
    close_sent: bool,
    close_received: bool,

    // ---- accounting -------------------------------------------------
    stats: Stats,
}

impl<R: Read, S: frame::FrameSink> Session<R, S> {
    /// Wrap a transport reader and a frame writer.
    ///
    /// `reader` must be the connection's buffered reader so that bytes
    /// read past the opening handshake are preserved; `writer` may be
    /// cloned (via the sink's own sharing) so application threads can
    /// push messages while this session reads.
    pub fn new(reader: BufReader<R>, writer: FrameWriter<S>, cfg: SessionConfig) -> Self {
        let inflater = cfg.compression.map(|c| Inflater::new(c.recv_window_bits));
        Self {
            reader,
            writer,
            cfg,
            phase: Phase::Header { filled: 0 },
            head: [0u8; MAX_HEADER_LEN],
            msg: Vec::new(),
            ctl: Vec::new(),
            msg_opcode: None,
            msg_compressed: false,
            fragments: 0,
            utf8: Utf8Validator::new(),
            inflater,
            dec_buf: Vec::new(),
            close_sent: false,
            close_received: false,
            stats: Stats::new(),
        }
    }

    /// The frame writer (so a caller can share it with other threads).
    pub fn writer(&self) -> &FrameWriter<S> {
        &self.writer
    }

    /// Mutable access to the frame writer.
    pub fn writer_mut(&mut self) -> &mut FrameWriter<S> {
        &mut self.writer
    }

    /// Access the transport's reader (e.g. to reclaim it after the
    /// session ends).
    pub fn into_parts(self) -> (BufReader<R>, FrameWriter<S>) {
        (self.reader, self.writer)
    }

    /// Mutable access to the buffered reader.
    pub fn reader_mut(&mut self) -> &mut BufReader<R> {
        &mut self.reader
    }

    /// The active configuration.
    pub fn config(&self) -> &SessionConfig {
        &self.cfg
    }

    /// Counters so far, read and write sides merged.
    pub fn stats(&self) -> Stats {
        let mut merged = self.stats;
        let w = self.writer.stats();
        merged.frames_written = w.frames_written;
        merged.messages_written = w.messages_written;
        merged.bytes_written = w.bytes_written;
        merged.pings_sent = w.pings_sent;
        merged.pongs_sent = w.pongs_sent;
        merged.compressed_written = w.compressed_written;
        merged.bytes_saved_written = w.bytes_saved_written;
        merged
    }

    /// Whether the closing handshake has completed in both directions, or
    /// a fatal error was already reported.
    pub fn is_finished(&self) -> bool {
        matches!(self.phase, Phase::Finished)
    }

    /// Whether we have sent our closing frame.
    pub fn close_sent(&self) -> bool {
        self.close_sent
    }

    /// Whether the peer's closing frame has been received.
    pub fn close_received(&self) -> bool {
        self.close_received
    }

    /// Record that a closing frame was written *outside* this session
    /// (an application closing through its own send handle). Keeps the
    /// state machine's view of the handshake consistent with the wire.
    pub fn note_close_sent(&mut self) {
        self.close_sent = true;
    }

    /// The negotiated compression parameters, if any.
    pub fn compression(&self) -> Option<CompressionParams> {
        self.cfg.compression
    }

    /// Install (or replace) the negotiated compression parameters.
    ///
    /// Call this when the opening handshake finishes *after* the session
    /// was constructed: the receive-side context is rebuilt from the
    /// negotiated window size, so a smaller window is never left with a
    /// larger one's history.
    pub fn set_compression(&mut self, params: Option<CompressionParams>) {
        self.cfg.compression = params;
        self.inflater = params.map(|c| Inflater::new(c.recv_window_bits));
        self.writer.set_compression(params);
    }

    // -----------------------------------------------------------------
    // Receiving
    // -----------------------------------------------------------------

    /// Drive the state machine until a message is complete.
    ///
    /// `Ok(None)` means "no complete frame yet": the caller parks the
    /// connection and calls again when the transport is readable. All
    /// partial state (frame bytes, UTF-8 sequence, reassembly buffer) is
    /// retained.
    pub fn poll_message(&mut self) -> Result<Option<Event>> {
        loop {
            match self.phase {
                Phase::Finished => {
                    return Err(Error::with_message(
                        ErrorKind::UnexpectedEof,
                        "websocket: session already closed",
                    ))
                }
                Phase::Header { .. } => match self.read_header()? {
                    Some(header) => self.begin_frame(header)?,
                    None => return Ok(None),
                },
                Phase::Payload { .. } => {
                    if !self.read_payload_step()? {
                        return Ok(None);
                    }
                    if let Some(event) = self.finish_frame()? {
                        return Ok(Some(event));
                    }
                }
            }
        }
    }

    /// Blocking convenience over [`Session::poll_message`].
    ///
    /// Returns `ErrorKind::WouldBlock` when the transport is
    /// non-blocking and has nothing buffered; callers driving an event
    /// loop must use `poll_message` instead, which is the primitive.
    pub fn read_message(&mut self) -> Result<Event> {
        match self.poll_message()? {
            Some(event) => Ok(event),
            None => Err(Error::new(ErrorKind::WouldBlock)),
        }
    }

    /// Parse the next frame header, using the buffered fast path when the
    /// whole header already sits in the read buffer.
    fn read_header(&mut self) -> Result<Option<FrameHeader>> {
        let mut filled = match self.phase {
            Phase::Header { filled } => filled,
            _ => 0,
        };

        // Fast path: header entirely buffered: parse without copying.
        if filled == 0 {
            let (need, ready) = {
                let buf = match self.reader.fill_buf() {
                    Ok([]) => return Err(Error::eof()),
                    Ok(b) => b,
                    Err(e) if e.kind == ErrorKind::WouldBlock => return Ok(None),
                    Err(e) => return Err(e),
                };
                match FrameHeader::header_len_hint(buf) {
                    Some(need) => (need, buf.len() >= need),
                    None => (2, false),
                }
            };
            if ready {
                let parsed = {
                    let buf = match self.reader.fill_buf() {
                        Ok([]) => return Err(Error::eof()),
                        Ok(b) => b,
                        Err(e) if e.kind == ErrorKind::WouldBlock => return Ok(None),
                        Err(e) => return Err(e),
                    };
                    FrameHeader::parse(&buf[..need])?
                };
                if let Some(header) = parsed {
                    self.reader.consume(need);
                    return Ok(Some(header));
                }
                // Unreachable in practice: `header_len_hint` mirrors the
                // parser. Fall through to the accumulating path so a
                // disagreement can never become a hang.
                debug_assert!(false, "header_len_hint disagrees with parse");
            }
        }

        // Slow path: accumulate the 2..=14 header bytes across reads.
        if filled < 2 {
            filled += self.reader.read_more(&mut self.head[filled..2])?;
            if filled < 2 {
                self.phase = Phase::Header { filled };
                return Ok(None);
            }
        }
        let need = FrameHeader::header_len_hint(&self.head[..2])
            .ok_or_else(|| Error::protocol("websocket: header length unavailable"))?;
        if filled < need {
            let (head, reader) = (&mut self.head, &mut self.reader);
            let filled_now = reader.read_more(&mut head[filled..need])?;
            filled += filled_now;
            if filled < need {
                self.phase = Phase::Header { filled };
                return Ok(None);
            }
        }
        let header = FrameHeader::parse(&self.head[..need])?
            .ok_or_else(|| Error::protocol("websocket: truncated frame header"))?;
        self.phase = Phase::Header { filled: 0 };
        Ok(Some(header))
    }

    /// Validate a header against the session state and start its payload.
    fn begin_frame(&mut self, header: FrameHeader) -> Result<()> {
        let compressed_allowed = self.cfg.compression.is_some();
        if let Err(e) = header.check_reserved(compressed_allowed) {
            return Err(self.fatal(e));
        }

        // §5.1: a server MUST close on an unmasked client frame, and a
        // client MUST close on a masked server frame. Getting this
        // backwards is how intermediaries get cache-poisoned.
        match self.cfg.role {
            Role::Server if !header.masked => {
                return Err(self.fatal(Error::protocol("websocket: client frame was not masked")))
            }
            Role::Client if header.masked => {
                return Err(self.fatal(Error::protocol("websocket: server masked a frame")))
            }
            _ => {}
        }

        if header.opcode.is_control() {
            // Control frames are validated by the parser (a 125-byte maximum,
            // never fragmented) and may interleave anywhere. They still have to
            // respect the configured frame cap, though, or `max_frame` would not
            // mean what it says for a session that sets it below 125.
            if header.payload_len > self.cfg.max_frame as u64 {
                return Err(self.fatal(Error::overflow(
                    "websocket: control frame exceeds the size limit",
                )));
            }
            self.ctl.clear();
            self.phase = Phase::Payload { header, got: 0 };
            self.stats.frames_read += 1;
            return Ok(());
        }

        // ---- data frames -------------------------------------------
        match (self.msg_opcode, header.opcode) {
            (None, OpCode::Continuation) => {
                return Err(self.fatal(Error::protocol(
                    "websocket: continuation frame without a started message",
                )))
            }
            (Some(_), OpCode::Continuation) => {
                self.fragments = self.fragments.saturating_add(1);
                self.stats.fragments_read += 1;
            }
            (None, OpCode::Text | OpCode::Binary) => {
                self.msg.clear();
                self.utf8.reset();
                self.msg_compressed = header.rsv1;
                self.fragments = 0;
            }
            (Some(_), OpCode::Text | OpCode::Binary) => {
                return Err(self.fatal(Error::protocol(
                    "websocket: data frame while a fragmented message is open",
                )))
            }
            _ => unreachable!("control frames handled above"),
        }

        if header.rsv1 && self.msg_opcode.is_some() {
            // RSV1 may only appear on the first frame of a message
            // (RFC 7692 §6: the compression flag is per message).
            return Err(self.fatal(Error::protocol(
                "websocket: RSV1 set on a continuation frame",
            )));
        }

        let total = (self.msg.len() as u64).saturating_add(header.payload_len);
        if header.payload_len > self.cfg.max_frame as u64 || total > self.cfg.max_message as u64 {
            // 1009 "message too big": reported as an overflow so the
            // server layer can answer with that code before closing.
            return Err(self.fatal(Error::overflow("websocket: message exceeds the size limit")));
        }
        if self.cfg.max_fragments != 0 && self.fragments >= self.cfg.max_fragments {
            return Err(self.fatal(Error::overflow("websocket: too many fragments")));
        }

        if self.msg_opcode.is_none() {
            self.msg_opcode = Some(header.opcode);
        }
        // Reserve up front (the common case is one frame carrying a whole
        // message) but cap the eager part: a peer announcing a gigabyte
        // and sending nothing must not commit one.
        const EAGER_RESERVE: u64 = 1 << 20;
        let want = core::cmp::min(total, EAGER_RESERVE) as usize;
        if self.msg.capacity() < want {
            self.msg.reserve(want - self.msg.len());
        }
        self.phase = Phase::Payload { header, got: 0 };
        self.stats.frames_read += 1;
        Ok(())
    }

    /// Move bytes from the transport into the frame's payload buffer.
    /// Returns `Ok(false)` when the transport would block.
    fn read_payload_step(&mut self) -> Result<bool> {
        let (header, mut got) = match self.phase {
            Phase::Payload { header, got } => (header, got),
            _ => return Ok(true),
        };
        let len = header.payload_len as usize;
        if got >= len {
            return Ok(true);
        }
        let is_control = header.opcode.is_control();
        let mask = if header.masked {
            Some(Mask::new(header.mask_key))
        } else {
            None
        };
        // Incremental UTF-8 validation only applies to an uncompressed
        // text message: compressed bytes are validated after inflating.
        let validate_text =
            !is_control && self.msg_opcode == Some(OpCode::Text) && !self.msg_compressed;

        loop {
            // Bulk fast path: when the internal read buffer is empty and a
            // large remainder of the payload is outstanding, read straight
            // into the message buffer. That is one transport read for up
            // to a whole socket buffer's worth of payload, with no copy
            // through the buffered reader — the difference between four
            // extra copies and none on a 256 KiB frame.
            let remaining = len - got;
            if !is_control && remaining >= DIRECT_READ_MIN && self.reader.buffered() == 0 {
                let start = self.msg.len();
                self.msg.resize(start + remaining, 0);
                let n = match self.reader.read_direct(&mut self.msg[start..]) {
                    Ok(n) => n,
                    Err(e) if e.kind == ErrorKind::WouldBlock || e.kind == ErrorKind::Timeout => {
                        self.msg.truncate(start);
                        self.phase = Phase::Payload { header, got };
                        return if e.kind == ErrorKind::WouldBlock {
                            Ok(false)
                        } else {
                            Err(e)
                        };
                    }
                    Err(e) => {
                        self.msg.truncate(start);
                        self.phase = Phase::Payload { header, got };
                        return Err(e);
                    }
                };
                self.msg.truncate(start + n);
                if let Some(m) = mask {
                    m.apply(got, &mut self.msg[start..]);
                }
                if validate_text {
                    if let Err(bad) = self.utf8.feed(&self.msg[start..]) {
                        let e =
                            Error::protocol(alloc::format!("websocket: {bad} in a text message"));
                        return Err(self.fatal(e));
                    }
                }
                got += n;
                if got >= len {
                    self.phase = Phase::Payload { header, got };
                    return Ok(true);
                }
                continue;
            }

            let take = {
                let buf = match self.reader.fill_buf() {
                    Ok([]) => return Err(Error::eof()),
                    Ok(b) => b,
                    Err(e) if e.kind == ErrorKind::WouldBlock => {
                        self.phase = Phase::Payload { header, got };
                        return Ok(false);
                    }
                    Err(e) => {
                        self.phase = Phase::Payload { header, got };
                        return Err(e);
                    }
                };
                let take = core::cmp::min(len - got, buf.len());
                if is_control {
                    let start = self.ctl.len();
                    self.ctl.extend_from_slice(&buf[..take]);
                    if let Some(m) = mask {
                        m.apply(got, &mut self.ctl[start..]);
                    }
                } else {
                    let start = self.msg.len();
                    self.msg.extend_from_slice(&buf[..take]);
                    if let Some(m) = mask {
                        m.apply(got, &mut self.msg[start..]);
                    }
                    if validate_text {
                        if let Err(bad) = self.utf8.feed(&self.msg[start..]) {
                            let e = Error::protocol(alloc::format!(
                                "websocket: {bad} in a text message"
                            ));
                            return Err(self.fatal(e));
                        }
                    }
                }
                take
            };
            self.reader.consume(take);
            got += take;
            if got >= len {
                self.phase = Phase::Payload { header, got };
                return Ok(true);
            }
        }
    }

    /// Handle a fully received frame.
    fn finish_frame(&mut self) -> Result<Option<Event>> {
        let header = match self.phase {
            Phase::Payload { header, .. } => header,
            _ => return Ok(None),
        };
        self.phase = Phase::Header { filled: 0 };
        match header.opcode {
            OpCode::Ping => {
                self.stats.pings_received += 1;
                let payload = core::mem::take(&mut self.ctl);
                if self.cfg.auto_pong && !self.close_sent && !self.writer.is_closed() {
                    // RFC 6455 §5.5.3: the Pong must carry the identical
                    // payload. Answering is mandatory; a peer that
                    // floods Pings is rate-limited by the transport's
                    // write path (and by the queue cap on the event
                    // path) rather than by silently dropping replies.
                    //
                    // Once the closing handshake started — including one
                    // started by the application's own writer on this
                    // connection — the reply is skipped instead of
                    // failing the read: the writer would refuse it, and a
                    // Ping arriving after our Close is not an error.
                    self.send_pong_inner(&payload)?;
                }
                Ok(Some(Event::Ping(Bytes::from(payload))))
            }
            OpCode::Pong => {
                self.stats.pongs_received += 1;
                let payload = core::mem::take(&mut self.ctl);
                Ok(Some(Event::Pong(Bytes::from(payload))))
            }
            OpCode::Close => {
                self.stats.closes += 1;
                let payload = core::mem::take(&mut self.ctl);
                let frame = match close::parse(&payload) {
                    Ok(f) => f,
                    Err(e) => {
                        // Echo a legal close code and stop: the peer's
                        // payload was unusable, but the handshake still
                        // has to complete (RFC 6455 §7.1.7).
                        let _ = self.close(close::PROTOCOL_ERROR, "");
                        self.close_received = true;
                        return Err(self.fatal(e));
                    }
                };
                self.close_received = true;
                if !self.close_sent {
                    let code = frame.as_ref().map(|f| f.code).unwrap_or(close::NORMAL);
                    let reason = frame.as_ref().map(|f| f.reason.as_str()).unwrap_or("");
                    self.close(code, reason)?;
                }
                self.phase = Phase::Finished;
                Ok(Some(Event::Close(frame)))
            }
            OpCode::Text | OpCode::Binary | OpCode::Continuation => {
                if !header.fin {
                    // Fragment accepted: keep reading.
                    return Ok(None);
                }
                let opcode = self
                    .msg_opcode
                    .ok_or_else(|| Error::protocol("websocket: message opcode lost"))?;
                let compressed = self.msg_compressed;
                self.msg_opcode = None;
                self.msg_compressed = false;

                let bytes: Vec<u8> = if compressed {
                    let inflater = self
                        .inflater
                        .as_mut()
                        .ok_or_else(|| Error::protocol("websocket: compressed frame unexpected"))?;
                    let max = self.cfg.max_message;
                    let mut dec = core::mem::take(&mut self.dec_buf);
                    let start = core::mem::take(&mut self.msg);
                    let r = inflater.inflate_message(&start, &mut dec, max);
                    self.msg = start;
                    match r {
                        Ok(()) => {
                            self.stats.compressed_read += 1;
                            core::mem::take(&mut dec)
                        }
                        Err(e) => {
                            self.dec_buf = dec;
                            return Err(self.fatal(e));
                        }
                    }
                } else {
                    core::mem::take(&mut self.msg)
                };

                self.stats.messages_read += 1;
                self.stats.bytes_read += bytes.len() as u64;
                match opcode {
                    OpCode::Text => {
                        if compressed {
                            // Compressed text could not be validated
                            // incrementally; check the whole message now.
                            if !Utf8Validator::validate(&bytes) {
                                return Err(self.fatal(Error::protocol(
                                    "websocket: invalid UTF-8 in a text message",
                                )));
                            }
                        } else if !self.utf8.is_complete() {
                            return Err(self.fatal(Error::protocol(
                                "websocket: text message ends inside a UTF-8 sequence",
                            )));
                        }
                        let text = String::from_utf8(bytes).map_err(|_| {
                            Error::protocol("websocket: invalid UTF-8 in a text message")
                        })?;
                        Ok(Some(Event::Text(text)))
                    }
                    _ => Ok(Some(Event::Binary(Bytes::from(bytes)))),
                }
            }
        }
    }

    // -----------------------------------------------------------------
    // Sending
    // -----------------------------------------------------------------

    /// Send a text message.
    pub fn send_text(&mut self, text: &str) -> Result<()> {
        self.writer.send_text(text)
    }

    /// Send a binary message.
    pub fn send_binary(&mut self, data: &[u8]) -> Result<()> {
        self.writer.send_binary(data)
    }

    /// Send a Ping (RFC 6455 §5.5.2 limits the payload to 125 bytes).
    pub fn send_ping(&mut self, payload: &[u8]) -> Result<()> {
        self.writer.send_ping(payload)
    }

    /// Send a Pong.
    pub fn send_pong(&mut self, payload: &[u8]) -> Result<()> {
        self.writer.send_pong(payload)
    }

    fn send_pong_inner(&mut self, payload: &[u8]) -> Result<()> {
        self.writer.send_pong(payload)
    }

    /// Start the closing handshake. Idempotent, and always uses a legal
    /// code: the codes that only exist locally (1005/1006/1015) are
    /// mapped to [`close::NORMAL`].
    pub fn close(&mut self, code: u16, reason: &str) -> Result<()> {
        if self.close_sent {
            return Ok(());
        }
        self.writer.send_close(code, reason)?;
        self.close_sent = true;
        self.stats.closes += 1;
        if self.close_received {
            self.phase = Phase::Finished;
        }
        Ok(())
    }

    /// Flush buffered output to the transport.
    pub fn flush(&mut self) -> Result<()> {
        self.writer.flush()
    }

    /// Record a fatal protocol violation: bump the counter, make the
    /// session terminal so no further application traffic can be read or
    /// written, and hand the error back to the caller (which decides
    /// which close code to send and why).
    fn fatal(&mut self, e: Error) -> Error {
        self.stats.violations += 1;
        self.phase = Phase::Finished;
        e
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::courierust_deflate::deflate_sync;
    use crate::courierust_io::{BufReader, SliceReader};
    use crate::courierust_ws::handshake::CompressionParams;
    use crate::courierust_ws::writer::VecSink;
    use alloc::vec;

    type TestSession = Session<SliceReader<'static>, VecSink>;

    /// Encode a frame the way a *client* sends it (masked), so the server
    /// side of a session accepts it.
    fn masked_frame(opcode: OpCode, payload: &[u8], fin: bool, rsv1: bool) -> Vec<u8> {
        let key = [0x11, 0x22, 0x33, 0x44];
        let header = FrameHeader {
            fin,
            rsv1,
            rsv2: false,
            rsv3: false,
            opcode,
            masked: true,
            mask_key: key,
            payload_len: payload.len() as u64,
            header_len: 0,
        };
        let mut out = vec![0u8; MAX_HEADER_LEN];
        let n = header.write(&mut out);
        out.truncate(n);
        let mut body = payload.to_vec();
        Mask::new(key).apply(0, &mut body);
        out.extend_from_slice(&body);
        out
    }

    fn server_on(input: &[u8], cfg: SessionConfig) -> TestSession {
        let leaked: &'static [u8] = alloc::boxed::Box::leak(input.to_vec().into_boxed_slice());
        let writer = FrameWriter::new(VecSink::new(), MaskSource::None, cfg.compression);
        Session::new(BufReader::new(SliceReader::new(leaked), 4096), writer, cfg)
    }

    fn server(input: &[u8]) -> TestSession {
        server_on(input, SessionConfig::default())
    }

    fn client() -> TestSession {
        // The production client configuration: fresh, unpredictable mask
        // key per frame from a CSPRNG-seeded stream.
        let cfg = SessionConfig {
            role: Role::Client,
            ..Default::default()
        };
        let writer = FrameWriter::new(VecSink::new(), MaskSource::Random, None);
        Session::new(BufReader::new(SliceReader::new(&[]), 4096), writer, cfg)
    }

    /// A client with a pinned mask key, for byte-exact expectations.
    fn client_fixed_key(key: [u8; 4]) -> TestSession {
        let cfg = SessionConfig {
            role: Role::Client,
            ..Default::default()
        };
        let writer = FrameWriter::new(VecSink::new(), MaskSource::Fixed(key), None);
        Session::new(BufReader::new(SliceReader::new(&[]), 4096), writer, cfg)
    }

    /// The bytes a session has written so far.
    fn out_bytes(s: &TestSession) -> &[u8] {
        &s.writer().sink().bytes
    }

    fn next(s: &mut TestSession) -> Result<Event> {
        s.read_message()
    }

    #[test]
    fn reads_a_single_text_message() {
        let mut wire = masked_frame(OpCode::Text, b"hello", true, false);
        wire.extend_from_slice(&masked_frame(OpCode::Text, b"world", true, false));
        let mut s = server(&wire);
        assert_eq!(next(&mut s).unwrap(), Event::Text(String::from("hello")));
        assert_eq!(next(&mut s).unwrap(), Event::Text(String::from("world")));
        assert!(next(&mut s).is_err(), "clean EOF must end the session");
        assert_eq!(s.stats().messages_read, 2);
    }

    #[test]
    fn reassembles_fragments_including_empty_ones() {
        let mut wire = Vec::new();
        wire.extend_from_slice(&masked_frame(OpCode::Text, b"", false, false));
        wire.extend_from_slice(&masked_frame(OpCode::Continuation, b"abc", false, false));
        wire.extend_from_slice(&masked_frame(OpCode::Continuation, b"", false, false));
        wire.extend_from_slice(&masked_frame(OpCode::Continuation, b"def", true, false));
        let mut s = server(&wire);
        assert_eq!(next(&mut s).unwrap(), Event::Text(String::from("abcdef")));
        assert_eq!(s.stats().fragments_read, 3);
    }

    #[test]
    fn surface_pings_and_answer_them() {
        let mut wire = masked_frame(OpCode::Ping, b"hi", true, false);
        wire.extend_from_slice(&masked_frame(OpCode::Pong, b"ho", true, false));
        let mut s = server(&wire);
        assert_eq!(next(&mut s).unwrap(), Event::Ping(Bytes::from(&b"hi"[..])));
        assert_eq!(next(&mut s).unwrap(), Event::Pong(Bytes::from(&b"ho"[..])));
        // The Pong we owe the peer must be on the wire, unmasked.
        let out = out_bytes(&s);
        let header = FrameHeader::parse(out).unwrap().unwrap();
        assert_eq!(header.opcode, OpCode::Pong);
        assert!(!header.masked);
        assert_eq!(header.payload_len, 2);
        assert_eq!(&out[header.header_len..], b"hi");
        assert_eq!(s.stats().pongs_sent, 1);
    }

    #[test]
    fn control_frames_interleave_with_fragments() {
        let mut wire = masked_frame(OpCode::Text, b"a", false, false);
        wire.extend_from_slice(&masked_frame(OpCode::Ping, b"p", true, false));
        wire.extend_from_slice(&masked_frame(OpCode::Continuation, b"b", true, false));
        let mut s = server(&wire);
        // The ping is surfaced before the message that is still open.
        assert_eq!(next(&mut s).unwrap(), Event::Ping(Bytes::from(&b"p"[..])));
        assert_eq!(next(&mut s).unwrap(), Event::Text(String::from("ab")));
    }

    #[test]
    fn close_handshake_is_echoed_and_terminates() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&1001u16.to_be_bytes());
        payload.extend_from_slice(b"going away");
        let wire = masked_frame(OpCode::Close, &payload, true, false);
        let mut s = server(&wire);
        let event = next(&mut s).unwrap();
        match event {
            Event::Close(Some(f)) => {
                assert_eq!(f.code, 1001);
                assert_eq!(f.reason, "going away");
            }
            other => panic!("expected close, got {other:?}"),
        }
        assert!(s.is_finished());
        let out = out_bytes(&s);
        let header = FrameHeader::parse(out).unwrap().unwrap();
        assert_eq!(header.opcode, OpCode::Close);
        // Our echo carries the same code.
        assert_eq!(
            u16::from_be_bytes([out[header.header_len], out[header.header_len + 1]]),
            1001
        );
        // Further reads fail: the session is terminal.
        assert!(next(&mut s).is_err());
    }

    #[test]
    fn empty_close_payload_is_answered_with_1000() {
        let wire = masked_frame(OpCode::Close, b"", true, false);
        let mut s = server(&wire);
        assert_eq!(next(&mut s).unwrap(), Event::Close(None));
        let out = out_bytes(&s);
        let header = FrameHeader::parse(out).unwrap().unwrap();
        assert_eq!(header.payload_len, 2);
        assert_eq!(
            u16::from_be_bytes([out[header.header_len], out[header.header_len + 1]]),
            1000
        );
    }

    #[test]
    fn rejects_unmasked_client_frames() {
        let mut h = FrameHeader::data(OpCode::Text, true, 2);
        h.masked = false;
        let mut wire = vec![0u8; MAX_HEADER_LEN];
        let n = h.write(&mut wire);
        wire.truncate(n);
        wire.extend_from_slice(b"hi");
        let mut s = server(&wire);
        let err = next(&mut s).unwrap_err();
        assert!(err.to_string().contains("not masked"), "{err}");
        assert_eq!(s.stats().violations, 1);
    }

    #[test]
    fn rejects_masked_server_frames_on_the_client() {
        let wire = masked_frame(OpCode::Text, b"hi", true, false);
        let cfg = SessionConfig {
            role: Role::Client,
            ..Default::default()
        };
        let leaked: &'static [u8] = alloc::boxed::Box::leak(wire.into_boxed_slice());
        let mut s = Session::new(
            BufReader::new(SliceReader::new(leaked), 4096),
            FrameWriter::new(VecSink::new(), MaskSource::Fixed([1, 2, 3, 4]), None),
            cfg,
        );
        assert!(next(&mut s).is_err());
    }

    #[test]
    fn enforces_frame_and_message_limits() {
        let cfg = SessionConfig {
            max_frame: 8,
            max_message: 16,
            ..Default::default()
        };
        // 9 bytes in one frame: over max_frame.
        let wire = masked_frame(OpCode::Binary, &[0u8; 9], true, false);
        let mut s = server_on(&wire, cfg.clone());
        assert!(next(&mut s).unwrap_err().to_string().contains("size limit"));
        // Eight-byte frames but a 24-byte message: over max_message.
        let mut wire = masked_frame(OpCode::Binary, &[0u8; 8], false, false);
        wire.extend_from_slice(&masked_frame(OpCode::Continuation, &[0u8; 8], false, false));
        wire.extend_from_slice(&masked_frame(OpCode::Continuation, &[0u8; 8], true, false));
        let mut s = server_on(&wire, cfg);
        assert!(next(&mut s).is_err());
    }

    #[test]
    fn enforces_the_fragment_count_limit() {
        let cfg = SessionConfig {
            max_fragments: 3,
            ..Default::default()
        };
        let mut wire = masked_frame(OpCode::Binary, b"a", false, false);
        for _ in 0..4 {
            wire.extend_from_slice(&masked_frame(OpCode::Continuation, b"a", false, false));
        }
        let mut s = server_on(&wire, cfg);
        assert!(next(&mut s).is_err());
    }

    #[test]
    fn rejects_invalid_utf8_in_text_early() {
        // 0xFF is never valid UTF-8: the session must fail on the frame
        // that carries it, not after buffering the whole message.
        let wire = masked_frame(OpCode::Text, &[0x41, 0xff, 0x42], true, false);
        let mut s = server(&wire);
        assert!(next(&mut s).is_err());
        assert_eq!(s.stats().violations, 1);
    }

    #[test]
    fn rejects_text_that_ends_inside_a_sequence() {
        let mut wire = masked_frame(OpCode::Text, &[0xe2], false, false);
        // Second fragment completes nothing: the message ends mid-sequence.
        wire.extend_from_slice(&masked_frame(OpCode::Continuation, &[0x41], true, false));
        let mut s = server(&wire);
        assert!(next(&mut s).is_err());
    }

    #[test]
    fn accepts_text_split_inside_a_sequence() {
        let emoji = "🦀".as_bytes();
        let mut wire = masked_frame(OpCode::Text, &emoji[..2], false, false);
        wire.extend_from_slice(&masked_frame(
            OpCode::Continuation,
            &emoji[2..],
            true,
            false,
        ));
        let mut s = server(&wire);
        assert_eq!(next(&mut s).unwrap(), Event::Text(String::from("🦀")));
    }

    #[test]
    fn rejects_structural_violations() {
        // Continuation without a started message.
        let wire = masked_frame(OpCode::Continuation, b"x", true, false);
        assert!(server(&wire).read_message().is_err());
        // A new data frame while a message is open.
        let mut wire = masked_frame(OpCode::Text, b"a", false, false);
        wire.extend_from_slice(&masked_frame(OpCode::Text, b"b", true, false));
        assert!(server(&wire).read_message().is_err());
        // RSV1 without a negotiated extension.
        let wire = masked_frame(OpCode::Text, b"a", true, true);
        assert!(server(&wire).read_message().is_err());
        // Non-minimal 16-bit length.
        let mut wire = vec![0x81u8, 0x80 | 126, 0x00, 0x05];
        wire.extend_from_slice(&[1, 2, 3, 4]);
        wire.extend_from_slice(b"hello");
        assert!(server(&wire).read_message().is_err());
        // Fragmented control frame.
        let wire = masked_frame(OpCode::Ping, b"x", false, false);
        assert!(server(&wire).read_message().is_err());
        // Reserved opcode 0x3.
        let wire = vec![0x83, 0x80, 1, 2, 3, 4];
        assert!(server(&wire).read_message().is_err());
    }

    /// A two-byte read buffer forces every frame to arrive in pieces; the
    /// session must resume exactly where it stopped.
    #[test]
    fn resumes_across_partial_reads() {
        let text = "a fragmented ünïcode 🦀 message";
        let mut wire = masked_frame(OpCode::Text, "a fragmented ".as_bytes(), false, false);
        wire.extend_from_slice(&masked_frame(
            OpCode::Continuation,
            "ünïcode 🦀".as_bytes(),
            false,
            false,
        ));
        wire.extend_from_slice(&masked_frame(
            OpCode::Continuation,
            " message".as_bytes(),
            true,
            false,
        ));
        let leaked: &'static [u8] = alloc::boxed::Box::leak(wire.into_boxed_slice());
        let mut s = Session::new(
            BufReader::new(SliceReader::new(leaked), 2),
            FrameWriter::new(VecSink::new(), MaskSource::None, None),
            SessionConfig::default(),
        );
        assert_eq!(next(&mut s).unwrap(), Event::Text(String::from(text)));
    }

    #[test]
    fn poll_returns_none_before_any_bytes_and_then_resumes() {
        // A session whose input arrives later: the first poll must report
        // "nothing yet" rather than an error.
        let wire = masked_frame(OpCode::Text, b"later", true, false);
        let leaked: &'static [u8] = alloc::boxed::Box::leak(wire.into_boxed_slice());
        let mut s = Session::new(
            BufReader::new(SliceReader::new(leaked), 4096),
            FrameWriter::new(VecSink::new(), MaskSource::None, None),
            SessionConfig::default(),
        );
        assert_eq!(
            s.poll_message().unwrap(),
            Some(Event::Text(String::from("later")))
        );
    }

    #[test]
    fn client_masks_every_frame_and_server_accepts_them() {
        let mut c = client();
        c.send_text("hello 🦀").unwrap();
        c.send_binary(&[1, 2, 3]).unwrap();
        c.send_ping(b"pp").unwrap();
        let out = c.writer().sink().bytes.clone();
        assert!(!out.is_empty());

        // Every frame must be masked, and the mask must differ per frame.
        let mut masks = Vec::new();
        let mut pos = 0usize;
        while pos < out.len() {
            let header = FrameHeader::parse(&out[pos..]).unwrap().unwrap();
            assert!(header.masked, "client frames must be masked");
            masks.push(header.mask_key);
            pos += header.header_len + header.payload_len as usize;
        }
        assert_eq!(masks.len(), 3);
        assert_ne!(masks[0], masks[1], "the key must change per frame");

        // The server decodes exactly what the client sent.
        let mut s = server(&out);
        assert_eq!(next(&mut s).unwrap(), Event::Text(String::from("hello 🦀")));
        assert_eq!(
            next(&mut s).unwrap(),
            Event::Binary(Bytes::from(&[1u8, 2, 3][..]))
        );
        assert_eq!(next(&mut s).unwrap(), Event::Ping(Bytes::from(&b"pp"[..])));
    }

    #[test]
    fn server_frames_are_never_masked() {
        let mut s = server(&[]);
        s.send_text("hi").unwrap();
        let out = out_bytes(&s);
        let header = FrameHeader::parse(out).unwrap().unwrap();
        assert!(!header.masked);
        assert_eq!(header.opcode, OpCode::Text);
        assert_eq!(&out[header.header_len..], b"hi");
    }

    #[test]
    fn compressed_messages_roundtrip_end_to_end() {
        let params = CompressionParams {
            send_window_bits: 15,
            send_no_context_takeover: false,
            recv_window_bits: 15,
            recv_no_context_takeover: false,
        };
        let text = "compress me ".repeat(200);
        let mut c = client();
        c.set_compression(Some(params));
        c.send_text(&text).unwrap();

        // The frame on the wire carries RSV1 and is smaller than the text.
        let out = c.writer().sink().bytes.clone();
        let header = FrameHeader::parse(&out).unwrap().unwrap();
        assert!(header.rsv1, "compressible payloads must be compressed");
        assert!((header.payload_len as usize) < text.len());
        assert_eq!(c.stats().compressed_written, 1);

        let mut s = server_on(
            &out,
            SessionConfig {
                compression: Some(params),
                ..Default::default()
            },
        );
        assert_eq!(next(&mut s).unwrap(), Event::Text(text));
        assert_eq!(s.stats().compressed_read, 1);
    }

    #[test]
    fn compressed_roundtrip_accepts_the_rfc7692_tail() {
        // The receiver must re-append 00 00 FF FF: hand it a payload that
        // a standard sender produces (tail already stripped) and check
        // that it inflates.
        let params = CompressionParams::default();
        let text = "0123456789".repeat(40);
        let body = deflate_sync(text.as_bytes());
        let mut s = server_on(
            &masked_frame(OpCode::Text, &body, true, true),
            SessionConfig {
                compression: Some(params),
                ..Default::default()
            },
        );
        assert_eq!(next(&mut s).unwrap(), Event::Text(text));
    }

    #[test]
    fn compressed_text_is_validated_after_inflating() {
        let params = CompressionParams::default();
        let bad = deflate_sync(&[0x41, 0xff, 0x41]);
        let wire = masked_frame(OpCode::Text, &bad, true, true);
        let mut s = server_on(
            &wire,
            SessionConfig {
                compression: Some(params),
                ..Default::default()
            },
        );
        assert!(next(&mut s).is_err());
    }

    #[test]
    fn rsv1_without_negotiation_is_rejected() {
        let wire = masked_frame(OpCode::Binary, b"data", true, true);
        assert!(server(&wire).read_message().is_err());
    }

    /// A compression bomb is bounded by the message limit, not by the
    /// peer's patience: the inflated size is what counts, so a small
    /// frame cannot expand into unbounded memory.
    #[test]
    fn a_decompression_bomb_hits_the_message_limit() {
        let params = CompressionParams::default();
        // ~64 KiB of highly repetitive data compresses to a few hundred
        // bytes; the session's limit is 1 KiB.
        let bomb = deflate_sync(&vec![0x41u8; 64 * 1024]);
        assert!(bomb.len() < 1024, "the compressed form must be small");
        let wire = masked_frame(OpCode::Binary, &bomb, true, true);
        let mut s = server_on(
            &wire,
            SessionConfig {
                compression: Some(params),
                max_message: 1024,
                ..Default::default()
            },
        );
        let err = next(&mut s).unwrap_err();
        assert_eq!(err.kind, ErrorKind::Overflow, "{err}");
        // The server layer maps an overflow to 1009 (“message too big”).
    }

    /// After the closing handshake starts, nothing may be sent
    /// (RFC 6455 §5.5.1) — on either side, and through either writer.
    #[test]
    fn sends_after_close_are_refused() {
        let mut s = server(&[]);
        s.send_text("ok").unwrap();
        s.close(close::NORMAL, "bye").unwrap();
        let written = out_bytes(&s).len();
        assert!(s.send_text("no").is_err());
        assert!(s.send_binary(b"no").is_err());
        assert!(s.send_ping(b"p").is_err());
        assert_eq!(out_bytes(&s).len(), written);
    }

    #[test]
    fn client_close_is_written_once_and_sends_a_legal_code() {
        let mut c = client_fixed_key([0xaa, 0xbb, 0xcc, 0xdd]);
        c.close(close::NORMAL, "bye").unwrap();
        c.close(close::NORMAL, "bye").unwrap(); // idempotent
        assert!(c.close_sent());
        let out = &c.writer().sink().bytes;
        let header = FrameHeader::parse(out).unwrap().unwrap();
        assert_eq!(header.opcode, OpCode::Close);
        assert_eq!(header.payload_len, 5);
        let body = &out[header.header_len..];
        let unmasked = {
            let mut b = body.to_vec();
            Mask::new(header.mask_key).apply(0, &mut b);
            b
        };
        assert_eq!(u16::from_be_bytes([unmasked[0], unmasked[1]]), 1000);
        assert_eq!(&unmasked[2..], b"bye");
        // A code that must never appear on the wire is replaced, not sent.
        let mut c = client_fixed_key([0xaa, 0xbb, 0xcc, 0xdd]);
        c.close(close::NO_STATUS, "").unwrap();
        let out = c.writer().sink().bytes.clone();
        let header = FrameHeader::parse(&out).unwrap().unwrap();
        let mut b = out[header.header_len..].to_vec();
        Mask::new(header.mask_key).apply(0, &mut b);
        assert_eq!(u16::from_be_bytes([b[0], b[1]]), 1000);
    }

    #[test]
    fn close_reason_is_truncated_on_a_char_boundary() {
        let mut c = client_fixed_key([0xaa, 0xbb, 0xcc, 0xdd]);
        let long_reason = "🦀".repeat(100); // 4 bytes each
        c.close(close::NORMAL, &long_reason).unwrap();
        let out = c.writer().sink().bytes.clone();
        let header = FrameHeader::parse(&out).unwrap().unwrap();
        assert!(header.payload_len <= 125);
        let body_len = header.payload_len as usize - 2;
        assert!(long_reason.is_char_boundary(body_len));
    }

    #[test]
    fn huge_payloads_are_masked_in_bounded_windows() {
        let mut c = client();
        let big = vec![0x5au8; 4 * 1024 * 1024];
        c.send_binary(&big).unwrap();
        // The whole frame is produced; the masking itself is streamed by
        // the sink in bounded windows, so a large message never needs a
        // large scratch buffer (or a second copy of the payload).
        assert!(out_bytes(&c).len() >= big.len());
        let out = c.writer().sink().bytes.clone();
        let header = FrameHeader::parse(&out).unwrap().unwrap();
        assert_eq!(header.payload_len, big.len() as u64);
        assert!(
            FrameHeader::header_len_hint(&out).unwrap() == 10 + 4,
            "64-bit length form expected"
        );
    }

    #[test]
    fn a_ping_payload_over_125_bytes_is_refused() {
        let mut c = client();
        assert!(c.send_ping(&[0u8; 126]).is_err());
        assert!(c.send_pong(&[0u8; 126]).is_err());
    }

    #[test]
    fn stats_account_for_traffic() {
        let wire = {
            let mut w = masked_frame(OpCode::Text, b"abc", true, false);
            w.extend_from_slice(&masked_frame(OpCode::Binary, &[7u8; 100], true, false));
            w
        };
        let mut s = server(&wire);
        assert_eq!(next(&mut s).unwrap(), Event::Text(String::from("abc")));
        assert_eq!(s.stats().frames_read, 1);
        assert!(matches!(next(&mut s).unwrap(), Event::Binary(_)));
        assert_eq!(s.stats().frames_read, 2);
        assert_eq!(s.stats().messages_read, 2);
        assert_eq!(s.stats().bytes_read, 103);
    }

    #[test]
    fn control_frame_with_max_payload_is_accepted() {
        let payload = vec![0u8; 125];
        let wire = masked_frame(OpCode::Ping, &payload, true, false);
        let mut s = server(&wire);
        assert!(matches!(next(&mut s).unwrap(), Event::Ping(_)));
        // ...and 126 must be rejected by the parser.
        let wire = masked_frame(OpCode::Ping, &[0u8; 126], true, false);
        let mut s = server(&wire);
        assert!(next(&mut s).is_err());
    }
}
