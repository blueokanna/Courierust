//! Incremental UTF-8 validation for WebSocket text frames.
//!
//! RFC 6455 §8.1 requires that a text message be valid UTF-8 *as a
//! whole*, and §5.6 allows a message to be split at arbitrary byte
//! boundaries. A validator that only checks each frame in isolation
//! therefore rejects legal messages (a three-byte character split across
//! two frames) and, worse, one that only checks at the end accepts
//! illegal ones long enough to buffer them. This module keeps the
//! decode state across frames: validation is exact and streaming.
//!
//! Two properties make it fast enough to sit in the receive path:
//!
//! * An ASCII fast path scans eight bytes per iteration with a single
//!   mask-and-branch (`w & 0x8080…`) while the decoder is in the ground
//!   state — the common case for chat/JSON traffic.
//! * The multi-byte path is a 12-state machine with *no table lookups*:
//!   restricted ranges (overlong, surrogate, and > U+10FFFF guards) are
//!   checked with two comparisons on the one continuation byte that
//!   needs them, exactly reproducing the well-formed byte-sequence table
//!   of Unicode §3.9.
//!
//! The rejection rules implemented here are the strict ones — no
//! “replacement character”, no lenient surrogate pass-through — because
//! a WebSocket endpoint that accepts a byte sequence its JSON parser
//! rejects (or vice versa) is an interop and smuggling surface.

use crate::courierust_error::Error;

/// Continuation ranges that depend on the lead byte (Unicode §3.9).
/// Index 0: `E0` (rejects overlong), 1: `ED` (rejects surrogates),
/// 2: `F0` (rejects overlong), 3: `F4` (rejects > U+10FFFF).
const RANGES: [(u8, u8); 4] = [(0xA0, 0xBF), (0x80, 0x9F), (0x90, 0xBF), (0x80, 0x8F)];

/// Decoder state, encoded in one byte so the whole validator is `Copy`
/// and fits in a register.
///
/// * `0` — ground: a new character may start.
/// * `1..=3` — `k` unrestricted continuation bytes (`80..=BF`) remain.
/// * `4..=7` — one continuation byte remains and it must fall inside
///   `RANGES[state - 4]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Utf8Validator {
    state: u8,
}

impl Utf8Validator {
    /// A fresh validator in the ground state.
    #[inline]
    pub const fn new() -> Self {
        Self { state: 0 }
    }

    /// Forget all partial state (start of a new message).
    #[inline]
    pub fn reset(&mut self) {
        self.state = 0;
    }

    /// Whether no partial character is pending — a message may only end
    /// here.
    #[inline]
    pub fn is_complete(&self) -> bool {
        self.state == 0
    }

    /// True when the last processed byte was a character start (so the
    /// ASCII fast path can be entered).
    #[inline]
    pub fn at_boundary(&self) -> bool {
        self.state == 0
    }

    /// Validate `bytes`, carrying partial-character state across calls.
    ///
    /// Returns the offset of the first invalid byte (relative to
    /// `bytes`) plus a stable reason, so a server can fail the
    /// connection with a precise log line instead of “bad UTF-8”.
    pub fn feed(&mut self, bytes: &[u8]) -> core::result::Result<(), Utf8Error> {
        let mut i = 0usize;
        // ---- ASCII fast path (only meaningful from the ground state) --
        if self.state == 0 {
            while i + 8 <= bytes.len() {
                let w = u64::from_ne_bytes(
                    bytes[i..i + 8]
                        .try_into()
                        .expect("slice of exactly 8 bytes"),
                );
                if w & 0x8080_8080_8080_8080 != 0 {
                    break;
                }
                i += 8;
            }
            while i < bytes.len() && bytes[i] < 0x80 {
                i += 1;
            }
            if i == bytes.len() {
                return Ok(());
            }
        }

        // ---- State machine for the multi-byte run ---------------------
        while i < bytes.len() {
            let b = bytes[i];
            match self.state {
                0 => {
                    self.state = match b {
                        0x00..=0x7F => 0,
                        0xC2..=0xDF => 1,
                        0xE1..=0xEC | 0xEE..=0xEF => 2,
                        0xE0 => 4,
                        0xED => 5,
                        0xF0 => 6,
                        0xF1..=0xF3 => 3,
                        0xF4 => 7,
                        // 80..=BF: bare continuation. C0/C1: overlong
                        // two-byte form. F5..=FF: above U+10FFFF.
                        _ => {
                            return Err(Utf8Error {
                                offset: i,
                                reason: "invalid lead byte",
                            })
                        }
                    };
                }
                1..=3 => {
                    if !(0x80..=0xBF).contains(&b) {
                        return Err(Utf8Error {
                            offset: i,
                            reason: "invalid continuation byte",
                        });
                    }
                    self.state -= 1;
                }
                _ => {
                    let idx = (self.state - 4) as usize;
                    let (lo, hi) = RANGES[idx];
                    if b < lo || b > hi {
                        return Err(Utf8Error {
                            offset: i,
                            reason: if idx == 1 {
                                "UTF-16 surrogate half is not a scalar value"
                            } else if idx == 3 {
                                "codepoint above U+10FFFF"
                            } else {
                                "overlong encoding"
                            },
                        });
                    }
                    // `E0`/`ED` are three-byte sequences (one continuation
                    // left); `F0`/`F4` are four-byte ones (two left).
                    self.state = if idx < 2 { 1 } else { 2 };
                }
            }
            i += 1;
        }
        Ok(())
    }

    /// Validate a complete message in one call.
    pub fn validate(bytes: &[u8]) -> bool {
        let mut v = Self::new();
        v.feed(bytes).is_ok() && v.is_complete()
    }
}

/// Where and why a text message was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Utf8Error {
    /// Byte offset of the offending sequence.
    pub offset: usize,
    /// Stable description (used in close-frame reasons and logs).
    pub reason: &'static str,
}

impl Utf8Error {
    /// Convert into the crate error type carried by protocol failures.
    ///
    /// The offset and reason travel with the message: a production log
    /// that says “invalid UTF-8 at byte 17: overlong encoding” is worth
    /// far more than one that says “bad text”. The server layer still
    /// maps it to close code 1007.
    pub fn into_error(self) -> Error {
        Error::protocol(alloc::format!(
            "websocket: invalid UTF-8 at byte {}: {}",
            self.offset,
            self.reason
        ))
    }
}

impl core::fmt::Display for Utf8Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "invalid UTF-8 at byte {}: {}", self.offset, self.reason)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    /// Every boundary character that a validator is likely to get wrong.
    #[test]
    fn boundary_scalars_are_accepted() {
        let cases: &[&str] = &[
            "",
            "a",
            "\u{7F}",
            "\u{80}",
            "\u{7FF}",
            "\u{800}",
            "\u{D7FF}",
            "\u{E000}",
            "\u{FFFF}",
            "\u{10000}",
            "\u{10FFFF}",
            "日本語テキスト 🚀 mixed ascii",
        ];
        for s in cases {
            assert!(Utf8Validator::validate(s.as_bytes()), "{s:?} must be valid");
        }
    }

    #[test]
    fn rejects_the_unicode_spec_falsehoods() {
        let cases: &[&[u8]] = &[
            &[0x80],                   // bare continuation
            &[0xC0, 0x80],             // overlong NUL
            &[0xC1, 0xBF],             // overlong
            &[0xE0, 0x80, 0x80],       // overlong
            &[0xE0, 0x9F, 0xBF],       // overlong (boundary)
            &[0xED, 0xA0, 0x80],       // surrogate half U+D800
            &[0xED, 0xBF, 0xBF],       // surrogate half U+DFFF
            &[0xF0, 0x80, 0x80, 0x80], // overlong
            &[0xF0, 0x8F, 0xBF, 0xBF], // overlong (boundary)
            &[0xF4, 0x90, 0x80, 0x80], // > U+10FFFF
            &[0xF5, 0x80, 0x80, 0x80], // lead out of range
            &[0xFF],                   // lead out of range
            &[0xC2],                   // truncated (incomplete)
            &[0xE2, 0x82],             // truncated
            &[0xF0, 0x9F, 0x98],       // truncated emoji
            &[0xE2, 0x28, 0xA1],       // invalid continuation
        ];
        for c in cases {
            let mut v = Utf8Validator::new();
            let ok = v.feed(c).is_ok() && v.is_complete();
            assert!(!ok, "{c:02x?} must be rejected");
        }
    }

    /// Cross-check against the standard library: for every two-byte
    /// input, acceptance must agree exactly. This is the strongest cheap
    /// oracle available for the state machine.
    #[test]
    fn agrees_with_std_for_all_two_byte_inputs() {
        for a in 0u16..=255 {
            for b in 0u16..=255 {
                let bytes = [a as u8, b as u8];
                let ours = Utf8Validator::validate(&bytes);
                let theirs = core::str::from_utf8(&bytes).is_ok();
                assert_eq!(ours, theirs, "disagreement on {bytes:02x?}");
            }
        }
    }

    /// …and for a deterministic pseudo-random sample of longer inputs.
    #[test]
    fn agrees_with_std_on_random_sequences() {
        let mut state = 0x1234_5678u32;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state
        };
        for _ in 0..20_000 {
            let len = (next() % 8) as usize + 1;
            let mut buf = Vec::with_capacity(len);
            for _ in 0..len {
                // Bias toward multi-byte leads so the state machine is
                // actually exercised.
                let r = next();
                buf.push(match r % 4 {
                    0 => (r >> 8) as u8,
                    1 => 0x80 | ((r >> 8) as u8 & 0x3f),
                    2 => 0xC0 | ((r >> 8) as u8 & 0x1f),
                    _ => 0xE0 | ((r >> 8) as u8 & 0x0f),
                });
            }
            let ours = Utf8Validator::validate(&buf);
            let theirs = core::str::from_utf8(&buf).is_ok();
            assert_eq!(ours, theirs, "disagreement on {buf:02x?}");
        }
    }

    /// A message split at *every* byte boundary must validate, and one
    /// split after a truncated sequence must only validate once the
    /// remaining bytes arrive.
    #[test]
    fn split_messages_keep_their_state() {
        let text = "日本語テキスト🚀 end";
        let bytes = text.as_bytes();
        for split in 0..=bytes.len() {
            let mut v = Utf8Validator::new();
            let _ = v.feed(&bytes[..split]);
            let _ = v.feed(&bytes[split..]);
            assert!(v.is_complete(), "split at {split} lost state");
        }
        // Split inside the emoji, then finish: valid.
        let emoji = "🚀".as_bytes();
        let mut v = Utf8Validator::new();
        assert!(v.feed(&emoji[..2]).is_ok());
        assert!(!v.is_complete());
        assert!(v.feed(&emoji[2..]).is_ok());
        assert!(v.is_complete());
        // Reset must clear a dangling partial sequence.
        let mut v = Utf8Validator::new();
        assert!(v.feed(&emoji[..2]).is_ok());
        v.reset();
        assert!(v.is_complete());
        assert!(v.feed(b"ok").is_ok());
    }

    #[test]
    fn error_reports_the_offending_offset() {
        let mut v = Utf8Validator::new();
        let e = v.feed(b"abc\xFF").unwrap_err();
        assert_eq!(e.offset, 3);
        assert!(!e.reason.is_empty());
    }
}
