//! Outbound frame writer: compression, masking and framing behind one
//! object.
//!
//! A server that accepts application-driven sends needs to write from a
//! thread that does not own the read loop, so the *frame* boundary lives
//! in this object: one acquisition of the sink's lock covers a whole
//! message, and two threads can never interleave a frame's bytes.
//!
//! Compression is per message and honest: a payload below the threshold,
//! or one that did not get smaller, is sent with RSV1 clear.

use crate::courierust_deflate::Deflater;
use crate::courierust_error::{Error, Result};
use crate::courierust_ws::frame::{self, FrameHeader, FrameSink, Mask, OpCode, MAX_HEADER_LEN};
use crate::courierust_ws::handshake::CompressionParams;
use crate::courierust_ws::session::{MaskSource, Stats};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

/// The connection-level “a Close frame has gone out” flag.
///
/// A WebSocket connection can have more than one writer over the same
/// sink: the session's (which answers Pings and echoes a peer's Close)
/// and the application's (which may push messages from another thread).
/// RFC 6455 §5.5.1 — nothing but the Close frame may follow the Close
/// frame — is a property of the *connection*, not of a writer, so the
/// flag lives here and is shared rather than duplicated. Without it, a
/// push that races a close writes a data frame after the close frame and
/// the peer is entitled to treat the connection as failed.
#[derive(Clone, Default)]
pub struct CloseFlag {
    set: Arc<AtomicBool>,
}

impl CloseFlag {
    /// A flag that is not set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether a Close frame has been written.
    #[inline]
    pub fn is_set(&self) -> bool {
        self.set.load(Ordering::Acquire)
    }

    /// Record that a Close frame was written; returns whether this call
    /// was the one that set it (the loser of a race gets `false`).
    #[inline]
    pub fn set(&self) -> bool {
        !self.set.swap(true, Ordering::AcqRel)
    }
}

impl core::fmt::Debug for CloseFlag {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CloseFlag")
            .field("set", &self.is_set())
            .finish()
    }
}

/// An in-memory [`FrameSink`]: every frame's bytes are appended to
/// [`VecSink::bytes`].
///
/// Handy for tests, examples, and callers that want to forward the bytes
/// to a transport of their own (a proxy, an in-memory pipe, an FFI
/// boundary).
#[derive(Debug, Default, Clone)]
pub struct VecSink {
    /// Concatenated frame bytes.
    pub bytes: Vec<u8>,
}

impl VecSink {
    /// An empty sink.
    pub fn new() -> Self {
        Self::default()
    }

    /// Take the buffered bytes, leaving the sink empty.
    pub fn take(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.bytes)
    }
}

impl FrameSink for VecSink {
    fn write_frame(&mut self, header: &[u8], payload: &[u8], mask: Option<Mask>) -> Result<()> {
        self.bytes.reserve(header.len() + payload.len());
        self.bytes.extend_from_slice(header);
        let start = self.bytes.len();
        self.bytes.extend_from_slice(payload);
        if let Some(m) = mask {
            m.apply(0, &mut self.bytes[start..]);
        }
        Ok(())
    }
}

/// Encodes and writes frames to a [`FrameSink`].
pub struct FrameWriter<S: FrameSink> {
    sink: S,
    compression: Option<CompressionParams>,
    deflater: Option<Deflater>,
    mask_source: MaskSource,
    #[cfg(feature = "std")]
    rng: Option<crate::courierust_tls::crypto::rng::ChaChaRng>,
    comp_buf: Vec<u8>,
    head: [u8; MAX_HEADER_LEN],
    stats: Stats,
    /// Shared with every other writer on this connection.
    close_flag: CloseFlag,
}

impl<S: FrameSink> FrameWriter<S> {
    /// Build a writer with its own close flag.
    ///
    /// `mask_source` must be [`MaskSource::None`] for a server (RFC 6455
    /// §5.1: servers must not mask) and [`MaskSource::Random`] for a
    /// client. A connection with a second writer (a server that pushes
    /// from application threads) must build both with
    /// [`FrameWriter::with_close_flag`] so a close on either side stops
    /// the other.
    pub fn new(sink: S, mask_source: MaskSource, compression: Option<CompressionParams>) -> Self {
        Self::with_close_flag(sink, mask_source, compression, CloseFlag::new())
    }

    /// Build a writer that shares `close_flag` with another writer on the
    /// same connection.
    pub fn with_close_flag(
        sink: S,
        mask_source: MaskSource,
        compression: Option<CompressionParams>,
        close_flag: CloseFlag,
    ) -> Self {
        let mut writer = Self {
            sink,
            compression: None,
            deflater: None,
            mask_source,
            #[cfg(feature = "std")]
            rng: None,
            comp_buf: Vec::new(),
            head: [0u8; MAX_HEADER_LEN],
            stats: Stats::new(),
            close_flag,
        };
        writer.set_compression(compression);
        writer
    }

    /// The flag this writer shares with the rest of its connection.
    #[inline]
    pub fn close_flag(&self) -> CloseFlag {
        self.close_flag.clone()
    }

    /// Install (or replace) the negotiated compression parameters.
    pub fn set_compression(&mut self, params: Option<CompressionParams>) {
        self.compression = params;
        self.deflater = params.map(|p| {
            let mut d = Deflater::new();
            d.set_threshold(64);
            // RFC 7692 §7.2.1: what we send must fit the window the peer
            // agreed to, which is the *send* direction of our role.
            d.set_window_bits(p.send_window_bits);
            d
        });
    }

    /// The negotiated compression, if any.
    pub fn compression(&self) -> Option<CompressionParams> {
        self.compression
    }

    /// The underlying sink.
    pub fn sink(&self) -> &S {
        &self.sink
    }

    /// Mutable access to the underlying sink.
    pub fn sink_mut(&mut self) -> &mut S {
        &mut self.sink
    }

    /// Consume the writer, returning the sink.
    pub fn into_sink(self) -> S {
        self.sink
    }

    /// Write-side counters.
    pub fn stats(&self) -> &Stats {
        &self.stats
    }

    /// Write-side counters (mutable, for merging into a session's view).
    pub fn stats_mut(&mut self) -> &mut Stats {
        &mut self.stats
    }

    /// Send a text message.
    pub fn send_text(&mut self, text: &str) -> Result<()> {
        self.send_message(OpCode::Text, text.as_bytes())
    }

    /// Send a binary message.
    pub fn send_binary(&mut self, data: &[u8]) -> Result<()> {
        self.send_message(OpCode::Binary, data)
    }

    /// Send a Ping (payload ≤ 125 bytes, RFC 6455 §5.5.2).
    pub fn send_ping(&mut self, payload: &[u8]) -> Result<()> {
        self.check_open()?;
        self.check_control(payload)?;
        self.write_frame(OpCode::Ping, payload, true, false)?;
        self.stats.pings_sent += 1;
        Ok(())
    }

    /// Send a Pong.
    pub fn send_pong(&mut self, payload: &[u8]) -> Result<()> {
        self.check_open()?;
        self.check_control(payload)?;
        self.write_frame(OpCode::Pong, payload, true, false)?;
        self.stats.pongs_sent += 1;
        Ok(())
    }

    /// Send a Close frame. The code is validated (and replaced by 1000
    /// when it is one of the codes that must never appear on the wire),
    /// and the reason is truncated on a UTF-8 boundary to fit the 125-byte
    /// control-frame limit.
    ///
    /// Idempotent: a second call is a no-op, and **every** send after it
    /// fails, because RFC 6455 §5.5.1 forbids sending anything else once
    /// the closing handshake has started. Enforcing that here — rather
    /// than in each caller — is what keeps a server that pushes from
    /// another thread from racing a close that already went out.
    pub fn send_close(&mut self, code: u16, reason: &str) -> Result<()> {
        if self.close_flag.is_set() {
            return Ok(());
        }
        let code = if frame::close::is_valid_to_send(code) {
            code
        } else {
            frame::close::NORMAL
        };
        let mut payload = [0u8; 2 + frame::MAX_CONTROL_PAYLOAD];
        payload[..2].copy_from_slice(&code.to_be_bytes());
        let max_reason = frame::MAX_CONTROL_PAYLOAD - 2;
        let mut end = reason.len().min(max_reason);
        while end > 0 && !reason.is_char_boundary(end) {
            end -= 1;
        }
        payload[2..2 + end].copy_from_slice(&reason.as_bytes()[..end]);
        self.write_frame(OpCode::Close, &payload[..2 + end], true, false)?;
        self.close_flag.set();
        Ok(())
    }

    /// Whether a Close frame has been written by any writer on this
    /// connection.
    #[inline]
    pub fn is_closed(&self) -> bool {
        self.close_flag.is_set()
    }

    /// Drain buffered output.
    pub fn flush(&mut self) -> Result<()> {
        self.sink.flush()
    }

    fn check_control(&self, payload: &[u8]) -> Result<()> {
        if payload.len() > frame::MAX_CONTROL_PAYLOAD {
            return Err(Error::overflow(
                "websocket: control frame payload over 125 bytes",
            ));
        }
        Ok(())
    }

    /// Refuse application traffic once the closing handshake started.
    fn check_open(&self) -> Result<()> {
        if self.close_flag.is_set() {
            return Err(Error::canceled("websocket: close frame already sent"));
        }
        Ok(())
    }

    /// Send a message, compressing when negotiated *and* profitable.
    pub fn send_message(&mut self, opcode: OpCode, data: &[u8]) -> Result<()> {
        self.check_open()?;
        if let Some(deflater) = self.deflater.as_mut() {
            let mut comp = core::mem::take(&mut self.comp_buf);
            let compressed = deflater.deflate_message(data, &mut comp).is_some();
            let result = if compressed {
                self.write_frame(opcode, &comp, true, true)
            } else {
                self.write_frame(opcode, data, true, false)
            };
            self.comp_buf = comp;
            result?;
            // Counters mean “written”, not “attempted”: a message that
            // failed to reach the transport must not show up in them.
            self.stats.messages_written += 1;
            if compressed {
                self.stats.compressed_written += 1;
                self.stats.bytes_saved_written += (data.len() - self.comp_buf.len()) as i64;
            }
            Ok(())
        } else {
            self.write_frame(opcode, data, true, false)?;
            self.stats.messages_written += 1;
            Ok(())
        }
    }

    /// Frame and write one message body.
    pub fn write_frame(
        &mut self,
        opcode: OpCode,
        payload: &[u8],
        fin: bool,
        rsv1: bool,
    ) -> Result<()> {
        debug_assert!(
            !opcode.is_control() || payload.len() <= frame::MAX_CONTROL_PAYLOAD,
            "control payload over 125 bytes"
        );
        let mask = self.next_mask();
        let header = FrameHeader {
            fin,
            rsv1,
            rsv2: false,
            rsv3: false,
            opcode,
            masked: mask.is_some(),
            mask_key: mask.map(|m| m.key()).unwrap_or([0; 4]),
            payload_len: payload.len() as u64,
            header_len: 0,
        };
        let n = header.write(&mut self.head);
        // One `write_frame` call per frame: the sink makes it atomic.
        self.sink.write_frame(&self.head[..n], payload, mask)?;
        self.stats.frames_written += 1;
        self.stats.bytes_written += (n + payload.len()) as u64;
        Ok(())
    }

    /// A fresh masking key for the next frame.
    ///
    /// RFC 6455 §5.3 requires a new, unpredictable key per frame. Keys
    /// come from a ChaCha20 stream seeded once per writer from the
    /// platform CSPRNG: stronger than mixing OS entropy per frame (a real
    /// CSPRNG stream, not a hash) and free of a syscall in the send path.
    fn next_mask(&mut self) -> Option<Mask> {
        match self.mask_source {
            MaskSource::None => None,
            MaskSource::Fixed(key) => Some(Mask::new(key)),
            #[cfg(feature = "std")]
            MaskSource::Random => {
                if self.rng.is_none() {
                    let addr_seed = self as *const Self as usize as u64;
                    let time_seed = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_nanos() as u64)
                        .unwrap_or(0);
                    let rng =
                        crate::courierust_tls::crypto::rng::ChaChaRng::new().unwrap_or_else(|| {
                            let mut seed = [0u8; 44];
                            seed[..8].copy_from_slice(&time_seed.to_le_bytes());
                            seed[8..16].copy_from_slice(&addr_seed.to_le_bytes());
                            seed[16..24].copy_from_slice(
                                &(self.head.as_ptr() as usize as u64).to_le_bytes(),
                            );
                            crate::courierust_tls::crypto::rng::ChaChaRng::from_seed(&seed)
                        });
                    self.rng = Some(rng);
                }
                let mut key = [0u8; 4];
                if let Some(rng) = self.rng.as_mut() {
                    rng.fill(&mut key);
                }
                Some(Mask::new(key))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_frames_carry_no_mask() {
        let mut w = FrameWriter::new(VecSink::new(), MaskSource::None, None);
        w.send_text("hi").unwrap();
        let bytes = &w.sink().bytes;
        let header = FrameHeader::parse(bytes).unwrap().unwrap();
        assert!(!header.masked);
        assert_eq!(header.opcode, OpCode::Text);
        assert_eq!(&bytes[header.header_len..], b"hi");
        assert_eq!(w.stats().messages_written, 1);
        assert_eq!(w.stats().bytes_written, 4);
    }

    #[test]
    fn client_frames_are_masked_with_fresh_keys() {
        let mut w = FrameWriter::new(VecSink::new(), MaskSource::Fixed([9, 8, 7, 6]), None);
        w.send_text("abc").unwrap();
        let bytes = &w.sink().bytes;
        let header = FrameHeader::parse(bytes).unwrap().unwrap();
        assert!(header.masked);
        assert_eq!(header.mask_key, [9, 8, 7, 6]);
        let mut body = bytes[header.header_len..].to_vec();
        Mask::new(header.mask_key).apply(0, &mut body);
        assert_eq!(body, b"abc");
    }

    #[test]
    fn compression_is_skipped_when_it_does_not_pay() {
        let params = CompressionParams::default();
        let mut w = FrameWriter::new(VecSink::new(), MaskSource::None, Some(params));
        // Tiny payload: below the threshold.
        w.send_text("small").unwrap();
        let header = FrameHeader::parse(&w.sink().bytes).unwrap().unwrap();
        assert!(!header.rsv1);
        // Compressible payload: RSV1 set and smaller.
        let mut w = FrameWriter::new(VecSink::new(), MaskSource::None, Some(params));
        let text = "abcabcabcabc".repeat(40);
        w.send_text(&text).unwrap();
        let header = FrameHeader::parse(&w.sink().bytes).unwrap().unwrap();
        assert!(header.rsv1);
        assert!((header.payload_len as usize) < text.len());
        assert!(w.stats().bytes_saved_written > 0);
    }

    #[test]
    fn control_payloads_are_bounded() {
        let mut w = FrameWriter::new(VecSink::new(), MaskSource::None, None);
        assert!(w.send_ping(&[0u8; 126]).is_err());
        assert!(w.send_pong(&[0u8; 126]).is_err());
        // …and the maximum legal control payload goes through.
        assert!(w.send_ping(&[0u8; 125]).is_ok());
    }

    #[test]
    fn close_reason_is_trimmed_to_fit() {
        let mut w = FrameWriter::new(VecSink::new(), MaskSource::None, None);
        w.send_close(frame::close::NORMAL, &"x".repeat(500))
            .unwrap();
        let header = FrameHeader::parse(&w.sink().bytes).unwrap().unwrap();
        assert_eq!(header.payload_len, 125);
        assert_eq!(header.opcode, OpCode::Close);
    }

    #[test]
    fn an_internal_close_code_is_replaced() {
        let mut w = FrameWriter::new(VecSink::new(), MaskSource::None, None);
        w.send_close(frame::close::ABNORMAL, "").unwrap();
        let bytes = &w.sink().bytes;
        let header = FrameHeader::parse(bytes).unwrap().unwrap();
        let code = u16::from_be_bytes([bytes[header.header_len], bytes[header.header_len + 1]]);
        assert_eq!(code, frame::close::NORMAL);
    }

    /// RFC 6455 §5.5.1: nothing may follow the Close frame.
    #[test]
    fn nothing_is_written_after_close() {
        let mut w = FrameWriter::new(VecSink::new(), MaskSource::None, None);
        w.send_text("before").unwrap();
        w.send_close(frame::close::NORMAL, "bye").unwrap();
        let after_close = w.sink().bytes.len();
        assert!(w.is_closed());

        assert!(w.send_text("after").is_err());
        assert!(w.send_binary(b"after").is_err());
        assert!(w.send_ping(b"p").is_err());
        assert!(w.send_pong(b"p").is_err());
        assert_eq!(w.sink().bytes.len(), after_close, "nothing may be written");
        assert_eq!(w.stats().messages_written, 1);

        // Closing again is a no-op rather than a second Close frame.
        w.send_close(frame::close::GOING_AWAY, "again").unwrap();
        assert_eq!(w.sink().bytes.len(), after_close);
    }

    /// Two writers on one connection (the server's session and the
    /// application handle) must agree about the close: a shared flag is
    /// what stops a push from racing a close that already went out.
    #[test]
    fn a_shared_close_flag_stops_the_other_writer() {
        let flag = CloseFlag::new();
        let mut session_writer =
            FrameWriter::with_close_flag(VecSink::new(), MaskSource::None, None, flag.clone());
        let mut app_writer =
            FrameWriter::with_close_flag(VecSink::new(), MaskSource::None, None, flag.clone());

        app_writer.send_text("hello").unwrap();
        session_writer.send_close(frame::close::NORMAL, "").unwrap();
        assert!(flag.is_set());
        assert!(
            app_writer.is_closed(),
            "the application writer sees the close"
        );
        assert!(app_writer.send_text("too late").is_err());
        assert!(app_writer.sink().bytes.len() < 20);
    }

    /// Counters mean “written”: a send that fails must not be counted.
    #[test]
    fn counters_only_count_writes() {
        let mut w = FrameWriter::new(VecSink::new(), MaskSource::None, None);
        w.send_close(frame::close::NORMAL, "").unwrap();
        let before = *w.stats();
        assert!(w.send_text("x").is_err());
        assert!(w.send_ping(b"p").is_err());
        let after = *w.stats();
        assert_eq!(after.messages_written, before.messages_written);
        assert_eq!(after.pings_sent, before.pings_sent);
        assert_eq!(after.frames_written, before.frames_written);
    }
}
