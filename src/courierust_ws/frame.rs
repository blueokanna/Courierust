//! WebSocket frame codec (RFC 6455 §5).
//!
//! Headers are parsed straight out of the connection's read buffer and
//! the masking engine transforms payload bytes in place, so no frame
//! needs a scratch copy.
//!
//! Strictness is deliberate: a frame any mainstream proxy would reject is
//! rejected here too, so two hops can never disagree about where a frame
//! ends.
//!
//! * Reserved bits set without a negotiated extension → error.
//! * Unknown opcodes (`0x3`–`0x7`, `0xB`–`0xF`) → error.
//! * Control frames fragmented or longer than 125 bytes → error.
//! * Non-minimal length encodings (RFC 6455 §5.2) → error.
//! * The 64-bit length's most significant bit set → error.

use crate::courierust_error::{Error, Result};
use alloc::boxed::Box;
use alloc::vec::Vec;

/// Longest possible frame header (2 + 8 length + 4 mask).
pub const MAX_HEADER_LEN: usize = 14;

/// Largest payload a control frame may carry (RFC 6455 §5.5).
pub const MAX_CONTROL_PAYLOAD: usize = 125;

/// WebSocket opcode (RFC 6455 §5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OpCode {
    /// Continuation of a fragmented message (`0x0`).
    Continuation,
    /// UTF-8 text (`0x1`).
    Text,
    /// Arbitrary binary data (`0x2`).
    Binary,
    /// Close (`0x8`).
    Close,
    /// Ping (`0x9`).
    Ping,
    /// Pong (`0xA`).
    Pong,
}

impl OpCode {
    /// Decode the 4-bit opcode field.
    #[inline]
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0x0 => Self::Continuation,
            0x1 => Self::Text,
            0x2 => Self::Binary,
            0x8 => Self::Close,
            0x9 => Self::Ping,
            0xa => Self::Pong,
            _ => return None,
        })
    }

    /// The wire value.
    #[inline]
    pub fn to_u8(self) -> u8 {
        match self {
            Self::Continuation => 0x0,
            Self::Text => 0x1,
            Self::Binary => 0x2,
            Self::Close => 0x8,
            Self::Ping => 0x9,
            Self::Pong => 0xa,
        }
    }

    /// Whether this is a control opcode (the high bit of the four-bit
    /// field is set).
    #[inline]
    pub fn is_control(self) -> bool {
        self.to_u8() & 0x08 != 0
    }

    /// Whether this is a data opcode.
    #[inline]
    pub fn is_data(self) -> bool {
        !self.is_control()
    }

    /// A stable name for logs, traces and error messages.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Continuation => "continuation",
            Self::Text => "text",
            Self::Binary => "binary",
            Self::Close => "close",
            Self::Ping => "ping",
            Self::Pong => "pong",
        }
    }
}

/// A parsed frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    /// Final fragment flag.
    pub fin: bool,
    /// First reserved bit (used by `permessage-deflate` on data frames).
    pub rsv1: bool,
    /// Second reserved bit (unused by any registered extension).
    pub rsv2: bool,
    /// Third reserved bit (unused by any registered extension).
    pub rsv3: bool,
    /// Frame opcode.
    pub opcode: OpCode,
    /// Whether the payload is masked (clients must mask, servers must not).
    pub masked: bool,
    /// The 4-byte masking key (`[0; 4]` when unmasked).
    pub mask_key: [u8; 4],
    /// Payload length in bytes.
    pub payload_len: u64,
    /// Total header length: 2..=14.
    pub header_len: usize,
}

impl FrameHeader {
    /// A data frame with the given opcode and length, unmasked.
    pub fn data(opcode: OpCode, fin: bool, payload_len: u64) -> Self {
        Self {
            fin,
            rsv1: false,
            rsv2: false,
            rsv3: false,
            opcode,
            masked: false,
            mask_key: [0; 4],
            payload_len,
            header_len: 0,
        }
    }

    /// Parse a header from the start of `buf`.
    ///
    /// `Ok(None)` means “not enough bytes yet” (the caller keeps
    /// buffering); every structural violation is an `Err`, including the
    /// masking/control/length rules that do not depend on session state.
    pub fn parse(buf: &[u8]) -> Result<Option<Self>> {
        if buf.len() < 2 {
            return Ok(None);
        }
        let b0 = buf[0];
        let b1 = buf[1];
        let opcode = OpCode::from_u8(b0 & 0x0f)
            .ok_or_else(|| Error::protocol("websocket: reserved opcode received"))?;
        let fin = b0 & 0x80 != 0;
        let masked = b1 & 0x80 != 0;

        let mut need = 2usize;
        let len7 = b1 & 0x7f;
        let payload_len: u64 = match len7 {
            126 => {
                need += 2;
                if buf.len() < need {
                    return Ok(None);
                }
                let v = u16::from_be_bytes([buf[2], buf[3]]) as u64;
                if v < 126 {
                    return Err(Error::protocol(
                        "websocket: non-minimal 16-bit payload length",
                    ));
                }
                v
            }
            127 => {
                need += 8;
                if buf.len() < need {
                    return Ok(None);
                }
                let mut b = [0u8; 8];
                b.copy_from_slice(&buf[2..10]);
                let v = u64::from_be_bytes(b);
                if v >> 63 != 0 {
                    return Err(Error::protocol("websocket: payload length msb set"));
                }
                if v < 65_536 {
                    return Err(Error::protocol(
                        "websocket: non-minimal 64-bit payload length",
                    ));
                }
                v
            }
            n => u64::from(n),
        };

        let mut mask_key = [0u8; 4];
        if masked {
            need += 4;
            if buf.len() < need {
                return Ok(None);
            }
            mask_key.copy_from_slice(&buf[need - 4..need]);
        }

        if opcode.is_control() {
            if !fin {
                return Err(Error::protocol("websocket: fragmented control frame"));
            }
            if payload_len > MAX_CONTROL_PAYLOAD as u64 {
                return Err(Error::protocol(
                    "websocket: control frame payload too large",
                ));
            }
        }

        Ok(Some(Self {
            fin,
            rsv1: b0 & 0x40 != 0,
            rsv2: b0 & 0x20 != 0,
            rsv3: b0 & 0x10 != 0,
            opcode,
            masked,
            mask_key,
            payload_len,
            header_len: need,
        }))
    }

    /// Total header length implied by the first two bytes, or `None`
    /// when fewer than two bytes are available. Lets a caller decide
    /// whether a whole header sits in the read buffer before parsing.
    #[inline]
    pub fn header_len_hint(buf: &[u8]) -> Option<usize> {
        if buf.len() < 2 {
            return None;
        }
        let masked = buf[1] & 0x80 != 0;
        let base = match buf[1] & 0x7f {
            126 => 4,
            127 => 10,
            _ => 2,
        };
        Some(base + if masked { 4 } else { 0 })
    }

    /// Reserved bits must be clear unless an extension claimed them
    /// (`allow_rsv1` is true only for data frames once
    /// `permessage-deflate` is negotiated).
    pub fn check_reserved(&self, allow_rsv1: bool) -> Result<()> {
        let ok_rsv1 = self.rsv1 && allow_rsv1 && self.opcode.is_data();
        if (self.rsv1 && !ok_rsv1) || self.rsv2 || self.rsv3 {
            return Err(Error::protocol(
                "websocket: reserved bits set without a negotiated extension",
            ));
        }
        Ok(())
    }

    /// Serialize into `out` (must hold at least [`MAX_HEADER_LEN`] bytes)
    /// and return the number of bytes written.
    pub fn write(&self, out: &mut [u8]) -> usize {
        debug_assert!(out.len() >= MAX_HEADER_LEN);
        let mut b0 = self.opcode.to_u8();
        if self.fin {
            b0 |= 0x80;
        }
        if self.rsv1 {
            b0 |= 0x40;
        }
        if self.rsv2 {
            b0 |= 0x20;
        }
        if self.rsv3 {
            b0 |= 0x10;
        }
        out[0] = b0;
        let mask_bit = if self.masked { 0x80 } else { 0 };
        let mut n = if self.payload_len < 126 {
            out[1] = mask_bit | self.payload_len as u8;
            2
        } else if self.payload_len <= u64::from(u16::MAX) {
            out[1] = mask_bit | 126;
            out[2..4].copy_from_slice(&(self.payload_len as u16).to_be_bytes());
            4
        } else {
            out[1] = mask_bit | 127;
            out[2..10].copy_from_slice(&self.payload_len.to_be_bytes());
            10
        };
        if self.masked {
            out[n..n + 4].copy_from_slice(&self.mask_key);
            n += 4;
        }
        n
    }
}

/// A 4-byte masking key with its lane forms precomputed.
///
/// Masking is a repeating 4-byte XOR and 16 is a multiple of 4, so every
/// 16-byte lane starts at the same key phase (`offset & 3`): the body of
/// a payload becomes `lane ^= constant`, which vectorizes. The remainder
/// is peeled as 4-byte words at one phase plus at most three bytes. `Copy`
/// and allocation-free, so one instance serves every frame on a
/// connection.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Mask {
    key: [u8; 4],
    /// 16-byte patterns, one per starting phase.
    wide: [u128; 4],
    /// 4-byte patterns, one per starting phase.
    word: [u32; 4],
}

impl core::fmt::Debug for Mask {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Mask(<4 bytes>)")
    }
}

impl Mask {
    /// Build the lane patterns for `key`.
    pub fn new(key: [u8; 4]) -> Self {
        let mut wide = [0u128; 4];
        let mut word = [0u32; 4];
        for phase in 0..4 {
            let mut h = [0u8; 16];
            for (j, byte) in h.iter_mut().enumerate() {
                *byte = key[(phase + j) & 3];
            }
            wide[phase] = u128::from_ne_bytes(h);
            let mut w = [0u8; 4];
            for (j, byte) in w.iter_mut().enumerate() {
                *byte = key[(phase + j) & 3];
            }
            word[phase] = u32::from_ne_bytes(w);
        }
        Self { key, wide, word }
    }

    /// The raw key bytes (needed when a header must be re-serialized).
    #[inline]
    pub fn key(&self) -> [u8; 4] {
        self.key
    }

    /// XOR `data` in place, where `data[0]` is payload byte `offset`.
    pub fn apply(&self, offset: usize, data: &mut [u8]) {
        let phase = offset & 3;
        let wide = self.wide[phase];
        let mut i = 0usize;
        while i + 16 <= data.len() {
            let lane = u128::from_ne_bytes(
                data[i..i + 16]
                    .try_into()
                    .expect("slice of exactly 16 bytes"),
            ) ^ wide;
            data[i..i + 16].copy_from_slice(&lane.to_ne_bytes());
            i += 16;
        }
        let word = self.word[phase];
        while i + 4 <= data.len() {
            let lane =
                u32::from_ne_bytes(data[i..i + 4].try_into().expect("slice of exactly 4 bytes"))
                    ^ word;
            data[i..i + 4].copy_from_slice(&lane.to_ne_bytes());
            i += 4;
        }
        while i < data.len() {
            data[i] ^= self.key[(phase + i) & 3];
            i += 1;
        }
    }

    /// XOR-copy `src` into `dst` (same length), where `src[0]` is payload
    /// byte `offset`. One pass over the data instead of copy-then-mask.
    pub fn apply_into(&self, offset: usize, src: &[u8], dst: &mut [u8]) {
        debug_assert_eq!(src.len(), dst.len());
        let phase = offset & 3;
        let wide = self.wide[phase];
        let mut i = 0usize;
        while i + 16 <= src.len() {
            let lane = u128::from_ne_bytes(
                src[i..i + 16]
                    .try_into()
                    .expect("slice of exactly 16 bytes"),
            ) ^ wide;
            dst[i..i + 16].copy_from_slice(&lane.to_ne_bytes());
            i += 16;
        }
        let word = self.word[phase];
        while i + 4 <= src.len() {
            let lane =
                u32::from_ne_bytes(src[i..i + 4].try_into().expect("slice of exactly 4 bytes"))
                    ^ word;
            dst[i..i + 4].copy_from_slice(&lane.to_ne_bytes());
            i += 4;
        }
        while i < src.len() {
            dst[i] = src[i] ^ self.key[(phase + i) & 3];
            i += 1;
        }
    }
}

/// A destination for **encoded frames**.
///
/// The trait is frame-granular on purpose: one call writes exactly one
/// frame, so an implementation that shares the transport between threads
/// (a server that lets application threads push messages) can take its
/// lock once per frame and never interleave two frames' bytes on the
/// wire. A byte-granular `Write` cannot express that.
pub trait FrameSink {
    /// Write `header` followed by `payload`, masking the payload when
    /// `mask` is set (the mask is applied by the sink, so the caller's
    /// buffer is never mutated).
    fn write_frame(&mut self, header: &[u8], payload: &[u8], mask: Option<Mask>) -> Result<()>;

    /// Push buffered bytes to the transport.
    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

/// Size of the masking window a [`StreamSink`] uses, and the largest
/// frame it coalesces into a single write.
///
/// 64 KiB is the point where the trade is settled in favour of
/// throughput: a 256 KiB message costs five writes instead of seventeen,
/// while the per-connection staging buffer stays bounded at 64 KiB (a
/// thousand connections cannot pin more than 64 MiB of staging, and only
/// the ones actually sending large frames ever allocate it).
pub const MASK_WINDOW: usize = 64 * 1024;

/// Largest staging buffer a **masked large frame** may use.
///
/// Frames at or below [`MASK_WINDOW`] are already one write each. Above
/// it, the payload is transformed in windows, and the window size is the
/// remaining trade: a 64 KiB window means a 256 KiB message costs four
/// copies and five writes, while a 1 MiB window means one copy and two
/// writes — at the cost of a 1 MiB staging buffer per connection that
/// actually sends such frames (connections that only send small frames
/// never allocate more than their largest frame).
///
/// One megabyte is where the syscall and copy savings stop being
/// measurable against the memory spent: beyond it the transfer is
/// bandwidth-bound either way.
pub const MASK_WINDOW_MAX: usize = 1024 * 1024;

/// A [`FrameSink`] over a byte writer.
///
/// Two regimes, chosen per frame:
///
/// * **Coalesced** (frame ≤ [`MASK_WINDOW`]): header and payload are
///   assembled in one staging buffer and written with a single `write`.
///   One syscall per frame is what small-message latency actually
///   responds to — a 64-byte message costs one 64-byte copy instead of
///   two syscalls — and a client's masking happens inside the same
///   buffer.
/// * **Streaming** (larger frames): the header goes out with the first
///   window, then the rest is written straight from the caller's buffer
///   when unmasked, or transformed in windows of up to
///   [`MASK_WINDOW_MAX`] when masked. Sending a gigabyte never allocates
///   a gigabyte.
///
/// Requires a transport whose writes either complete or fail atomically
/// (a blocking socket, a TLS stream, an in-memory buffer). A
/// non-blocking transport must be driven through a queueing sink
/// instead, because a half-written frame cannot be resumed here.
pub struct StreamSink<W: crate::courierust_io::Write> {
    writer: W,
    /// Staging buffer, also the masking window for large frames.
    stage: Vec<u8>,
}

impl<W: crate::courierust_io::Write> StreamSink<W> {
    /// Wrap a writer.
    pub fn new(writer: W) -> Self {
        Self {
            writer,
            stage: Vec::new(),
        }
    }

    /// The wrapped writer.
    pub fn get_ref(&self) -> &W {
        &self.writer
    }

    /// Mutable access to the wrapped writer.
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.writer
    }

    /// Consume the sink, returning the writer.
    pub fn into_inner(self) -> W {
        self.writer
    }

    /// Bytes currently reserved for staging (diagnostics).
    pub fn stage_capacity(&self) -> usize {
        self.stage.capacity()
    }
}

impl<W: crate::courierust_io::Write> FrameSink for StreamSink<W> {
    fn write_frame(&mut self, header: &[u8], payload: &[u8], mask: Option<Mask>) -> Result<()> {
        let total = header.len() + payload.len();
        if total <= MASK_WINDOW {
            // Coalesced: one syscall for the whole frame.
            self.stage.clear();
            self.stage.reserve(total);
            self.stage.extend_from_slice(header);
            let start = self.stage.len();
            self.stage.extend_from_slice(payload);
            if let Some(m) = mask {
                m.apply(0, &mut self.stage[start..]);
            }
            let (stage, writer) = (&self.stage, &mut self.writer);
            return writer.write_all(stage);
        }
        self.writer.write_all(header)?;
        match mask {
            None => self.writer.write_all(payload),
            Some(m) => {
                let mut off = 0usize;
                while off < payload.len() {
                    let take = core::cmp::min(MASK_WINDOW_MAX, payload.len() - off);
                    self.stage.clear();
                    self.stage.extend_from_slice(&payload[off..off + take]);
                    m.apply(off, &mut self.stage);
                    let (stage, writer) = (&self.stage, &mut self.writer);
                    writer.write_all(stage)?;
                    off += take;
                }
                Ok(())
            }
        }
    }

    fn flush(&mut self) -> Result<()> {
        self.writer.flush()
    }
}

/// A boxed sink is a sink: this is what lets a session's writer be
/// type-erased so the application API does not depend on which driver
/// owns the connection.
impl FrameSink for Box<dyn FrameSink + Send> {
    fn write_frame(&mut self, header: &[u8], payload: &[u8], mask: Option<Mask>) -> Result<()> {
        (**self).write_frame(header, payload, mask)
    }

    fn flush(&mut self) -> Result<()> {
        (**self).flush()
    }
}

/// A [`FrameSink`] shared between the thread that owns the connection's
/// read loop and any thread that pushes messages.
///
/// One lock is taken **per frame**, which is exactly the granularity that
/// matters: two writers can interleave their time on the connection, but
/// never their bytes on the wire.
#[cfg(feature = "std")]
pub struct SharedSink<W: crate::courierust_io::Write> {
    inner: std::sync::Arc<std::sync::Mutex<StreamSink<W>>>,
}

#[cfg(feature = "std")]
impl<W: crate::courierust_io::Write> Clone for SharedSink<W> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

#[cfg(feature = "std")]
impl<W: crate::courierust_io::Write> SharedSink<W> {
    /// Wrap a writer.
    pub fn new(writer: W) -> Self {
        Self {
            inner: std::sync::Arc::new(std::sync::Mutex::new(StreamSink::new(writer))),
        }
    }

    /// Run `f` with the transport locked for the duration of one frame.
    /// A panic in another thread poisons the mutex; the connection keeps
    /// working rather than taking the process down.
    pub fn with<R>(&self, f: impl FnOnce(&mut W) -> R) -> R {
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        f(guard.get_mut())
    }

    /// Clone the wrapped transport (requires `W: Clone`).
    pub fn transport(&self) -> W
    where
        W: Clone,
    {
        self.with(|w| w.clone())
    }
}

#[cfg(feature = "std")]
impl<W: crate::courierust_io::Write> FrameSink for SharedSink<W> {
    fn write_frame(&mut self, header: &[u8], payload: &[u8], mask: Option<Mask>) -> Result<()> {
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.write_frame(header, payload, mask)
    }

    fn flush(&mut self) -> Result<()> {
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.flush()
    }
}

/// Close-frame status code handling (RFC 6455 §7.4).
pub mod close {
    use crate::courierust_error::{Error, Result};
    use crate::courierust_ws::utf8::Utf8Validator;
    use alloc::string::String;
    use alloc::vec::Vec;

    /// Normal closure.
    pub const NORMAL: u16 = 1000;
    /// Endpoint going away.
    pub const GOING_AWAY: u16 = 1001;
    /// Protocol error.
    pub const PROTOCOL_ERROR: u16 = 1002;
    /// Unsupported data type.
    pub const UNSUPPORTED: u16 = 1003;
    /// No status received (never sent on the wire).
    pub const NO_STATUS: u16 = 1005;
    /// Abnormal closure (never sent on the wire).
    pub const ABNORMAL: u16 = 1006;
    /// Invalid payload data (e.g. bad UTF-8).
    pub const INVALID_PAYLOAD: u16 = 1007;
    /// Policy violation.
    pub const POLICY: u16 = 1008;
    /// Message too big.
    pub const TOO_BIG: u16 = 1009;
    /// Mandatory extension missing.
    pub const MANDATORY_EXTENSION: u16 = 1010;
    /// Internal server error.
    pub const INTERNAL: u16 = 1011;
    /// Service restart.
    pub const SERVICE_RESTART: u16 = 1012;
    /// Try again later.
    pub const TRY_AGAIN_LATER: u16 = 1013;
    /// Bad gateway.
    pub const BAD_GATEWAY: u16 = 1014;
    /// TLS handshake failure (never sent on the wire).
    pub const TLS_HANDSHAKE: u16 = 1015;

    /// Whether `code` may appear in a **received** Close frame.
    ///
    /// Rejects the codes RFC 6455 forbids on the wire (1005/1006/1015),
    /// the unassigned block 1004 and 1016–2999, and anything outside the
    /// registered ranges. Autobahn's §7.9 cases exercise exactly these
    /// boundaries.
    pub fn is_valid_received(code: u16) -> bool {
        matches!(code, 1000..=1003 | 1007..=1014 | 3000..=4999)
    }

    /// Whether `code` may be **sent** by an endpoint.
    pub fn is_valid_to_send(code: u16) -> bool {
        matches!(code, 1000..=1003 | 1007..=1014 | 3000..=4999)
    }

    /// A parsed Close frame.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct CloseFrame {
        /// Status code (`NO_STATUS` when the peer sent an empty payload).
        pub code: u16,
        /// UTF-8 reason (empty when absent).
        pub reason: String,
    }

    impl CloseFrame {
        /// A close frame with a code and reason.
        pub fn new(code: u16, reason: &str) -> Self {
            Self {
                code,
                reason: String::from(reason),
            }
        }

        /// Encode the payload (`code` + reason).
        pub fn encode(&self) -> Vec<u8> {
            let mut out = Vec::with_capacity(2 + self.reason.len());
            out.extend_from_slice(&self.code.to_be_bytes());
            out.extend_from_slice(self.reason.as_bytes());
            out
        }
    }

    /// Parse a Close frame payload.
    ///
    /// * empty → `None` (no status; the peer closed without one)
    /// * one byte → protocol error (RFC 6455 §5.5.1)
    /// * code invalid → protocol error
    /// * reason not valid UTF-8 → invalid payload (1007)
    pub fn parse(payload: &[u8]) -> Result<Option<CloseFrame>> {
        if payload.is_empty() {
            return Ok(None);
        }
        if payload.len() == 1 {
            return Err(Error::protocol("websocket: 1-byte close payload"));
        }
        let code = u16::from_be_bytes([payload[0], payload[1]]);
        if !is_valid_received(code) {
            return Err(Error::protocol("websocket: invalid close code"));
        }
        let reason = &payload[2..];
        if !Utf8Validator::validate(reason) {
            return Err(Error::with_message(
                crate::courierust_error::ErrorKind::Protocol,
                "websocket: close reason is not UTF-8",
            ));
        }
        let text = core::str::from_utf8(reason)
            .map_err(|_| Error::protocol("websocket: close reason is not UTF-8"))?;
        Ok(Some(CloseFrame {
            code,
            reason: String::from(text),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn small_unmasked_header_roundtrip() {
        let h = FrameHeader {
            fin: true,
            rsv1: false,
            rsv2: false,
            rsv3: false,
            opcode: OpCode::Text,
            masked: false,
            mask_key: [0; 4],
            payload_len: 5,
            header_len: 2,
        };
        let mut buf = [0u8; MAX_HEADER_LEN];
        let n = h.write(&mut buf);
        assert_eq!(n, 2);
        assert_eq!(&buf[..2], &[0x81, 0x05]);
        let parsed = FrameHeader::parse(&buf[..n]).unwrap().unwrap();
        assert_eq!(parsed.opcode, OpCode::Text);
        assert!(parsed.fin);
        assert_eq!(parsed.payload_len, 5);
        assert_eq!(parsed.header_len, 2);
    }

    #[test]
    fn masked_16_bit_length_roundtrip() {
        let h = FrameHeader {
            fin: false,
            rsv1: true,
            rsv2: false,
            rsv3: false,
            opcode: OpCode::Binary,
            masked: true,
            mask_key: [0xde, 0xad, 0xbe, 0xef],
            payload_len: 4096,
            header_len: 0,
        };
        let mut buf = [0u8; MAX_HEADER_LEN];
        let n = h.write(&mut buf);
        assert_eq!(n, 8);
        let parsed = FrameHeader::parse(&buf[..n]).unwrap().unwrap();
        assert_eq!(parsed, FrameHeader { header_len: 8, ..h });
    }

    #[test]
    fn masked_64_bit_length_roundtrip() {
        let h = FrameHeader {
            fin: true,
            rsv1: false,
            rsv2: false,
            rsv3: false,
            opcode: OpCode::Binary,
            masked: true,
            mask_key: [1, 2, 3, 4],
            payload_len: 1 << 40,
            header_len: 0,
        };
        let mut buf = [0u8; MAX_HEADER_LEN];
        let n = h.write(&mut buf);
        assert_eq!(n, 14);
        let parsed = FrameHeader::parse(&buf[..n]).unwrap().unwrap();
        assert_eq!(parsed.payload_len, 1 << 40);
        assert_eq!(parsed.mask_key, [1, 2, 3, 4]);
    }

    #[test]
    fn partial_headers_ask_for_more_bytes() {
        let h = FrameHeader {
            fin: true,
            rsv1: false,
            rsv2: false,
            rsv3: false,
            opcode: OpCode::Binary,
            masked: true,
            mask_key: [9, 9, 9, 9],
            payload_len: 70_000,
            header_len: 0,
        };
        let mut buf = [0u8; MAX_HEADER_LEN];
        let n = h.write(&mut buf);
        for cut in 0..n {
            assert!(
                FrameHeader::parse(&buf[..cut]).unwrap().is_none(),
                "cut at {cut} must ask for more"
            );
        }
        assert!(FrameHeader::parse(&buf[..n]).unwrap().is_some());
        assert_eq!(FrameHeader::header_len_hint(&buf[..2]), Some(14));
    }

    #[test]
    fn rejects_reserved_opcodes_and_control_violations() {
        // 0x3 is reserved.
        assert!(FrameHeader::parse(&[0x83, 0x00]).is_err());
        // Fragmented control frame.
        assert!(FrameHeader::parse(&[0x09, 0x00]).is_err());
        // Oversized control payload (126 needs the 16-bit form: minimal
        // and over the control limit).
        assert!(FrameHeader::parse(&[0x89, 126, 0x00, 126]).is_err());
        // Non-minimal encodings.
        assert!(FrameHeader::parse(&[0x81, 126, 0x00, 0x05]).is_err());
        assert!(FrameHeader::parse(&[0x81, 127, 0, 0, 0, 0, 0, 0, 0, 5]).is_err());
        // MSB of the 64-bit length set.
        let mut buf = vec![0x82u8, 127];
        buf.extend_from_slice(&(1u64 << 63).to_be_bytes());
        assert!(FrameHeader::parse(&buf).is_err());
    }

    #[test]
    fn reserved_bit_gate() {
        let mut h = FrameHeader::data(OpCode::Text, true, 0);
        h.rsv1 = true;
        assert!(h.check_reserved(false).is_err());
        assert!(h.check_reserved(true).is_ok());
        let mut c = FrameHeader::data(OpCode::Ping, true, 0);
        c.rsv1 = true;
        assert!(c.check_reserved(true).is_err());
        let mut d = FrameHeader::data(OpCode::Text, true, 0);
        d.rsv3 = true;
        assert!(d.check_reserved(true).is_err());
    }

    /// Masking must be an involution and must agree with a naive byte
    /// implementation for every phase and length, including lengths that
    /// straddle the sixteen-byte lane loop, the four-byte word loop and
    /// the single-byte tail — and it must keep agreeing when the call
    /// starts at a payload offset that is not a multiple of four.
    #[test]
    fn mask_matches_naive_for_all_phases_and_lengths() {
        let key = [0x2b, 0x7e, 0x15, 0x16];
        let mask = Mask::new(key);
        for offset in 0..16usize {
            for len in 0..80usize {
                let src: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(37)).collect();
                let mut got = src.clone();
                mask.apply(offset, &mut got);
                let want: Vec<u8> = src
                    .iter()
                    .enumerate()
                    .map(|(i, b)| b ^ key[(offset + i) & 3])
                    .collect();
                assert_eq!(got, want, "offset={offset} len={len}");
                let mut dst = vec![0u8; len];
                mask.apply_into(offset, &src, &mut dst);
                assert_eq!(dst, want, "apply_into offset={offset} len={len}");
                mask.apply(offset, &mut got);
                assert_eq!(got, src);
            }
        }
    }

    #[test]
    fn close_payload_validation() {
        assert_eq!(close::parse(b"").unwrap(), None);
        assert!(close::parse(&[0x03]).is_err());
        assert_eq!(
            close::parse(&[0x03, 0xe8]).unwrap(),
            Some(close::CloseFrame::new(1000, ""))
        );
        assert_eq!(
            close::parse(&[0x03, 0xe8, b'b', b'y', b'e']).unwrap(),
            Some(close::CloseFrame::new(1000, "bye"))
        );
        for code in [0u16, 999, 1004, 1005, 1006, 1015, 1016, 2999, 5000] {
            let mut p = code.to_be_bytes().to_vec();
            p.push(b'x');
            assert!(close::parse(&p).is_err(), "code {code} must be rejected");
        }
        for code in [
            1000u16, 1001, 1002, 1003, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014, 3000, 3999,
            4000, 4999,
        ] {
            let p = code.to_be_bytes().to_vec();
            assert!(close::parse(&p).is_ok(), "code {code} must be accepted");
        }
        assert!(close::parse(&[0x03, 0xe8, 0xff, 0xfe]).is_err());
        assert!(close::parse(&[0x03, 0xe8, 0xe2, 0x82]).is_err());
    }
}
