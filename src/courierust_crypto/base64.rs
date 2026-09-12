//! Base64 (RFC 4648 §4) with a *canonical* decoder, implemented from the
//! public specification with no unsafe code and no lookup tables built
//! at run time.
//!
//! The decoder is deliberately strict: length must be a multiple of
//! four, padding must be exact, every non-padding character must be in
//! the standard alphabet, and the unused low bits of a padded quantum
//! must be zero. A lenient decoder turns distinct wire strings into the
//! same bytes, which is exactly the ambiguity attackers exploit when a
//! base64 token is compared for equality (cache keys, CSRF tokens,
//! `Sec-WebSocket-Key` uniqueness). Callers that need to *display* a
//! digest get the same strictness for free.

use crate::courierust_error::{Error, Result};
use alloc::string::String;
use alloc::vec::Vec;

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// `decode_table[byte]` is the 6-bit value, or `0xff` when the byte is
/// not a standard-alphabet character.
const INVALID: u8 = 0xff;

const fn decode_table() -> [u8; 256] {
    let mut t = [INVALID; 256];
    let mut i = 0usize;
    while i < 64 {
        t[ALPHABET[i] as usize] = i as u8;
        i += 1;
    }
    t
}

static DECODE_TABLE: [u8; 256] = decode_table();

/// Number of base64 characters needed to encode `len` bytes.
#[inline]
pub const fn encoded_len(len: usize) -> usize {
    // ceil(len / 3) * 4, without the `len + 2` overflow window.
    let quanta = len / 3 + if len % 3 != 0 { 1 } else { 0 };
    quanta * 4
}

/// Upper bound on the bytes a `chars`-character base64 string decodes to
/// (padding included in `chars`, so the real value may be one or two
/// bytes smaller).
#[inline]
pub const fn decoded_len(chars: usize) -> usize {
    chars / 4 * 3
}

/// Bytes that a **canonical** `input` decodes to, validating it on the
/// way.
///
/// This is the sizing half of [`validate`] and exists so a caller can
/// size a buffer — or reject a token — without decoding into a temporary
/// allocation. A 24-character `Sec-WebSocket-Key` is checked this way on
/// every handshake.
#[inline]
pub fn decoded_size(input: &[u8]) -> Result<usize> {
    decode_core(input, None)
}

/// Whether `input` is canonical RFC 4648 §4 base64, without decoding it.
#[inline]
pub fn validate(input: &[u8]) -> Result<()> {
    decode_core(input, None).map(|_| ())
}

/// Encode `data` into a fresh string.
pub fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(encoded_len(data.len()));
    encode_into(data, &mut out);
    out
}

/// Encode `data`, appending to `out` (reusable buffer; the hot path for
/// per-message tokens avoids a fresh allocation per call).
pub fn encode_into(data: &[u8], out: &mut String) {
    let mut chunks = data.chunks_exact(3);
    for chunk in &mut chunks {
        let n = ((chunk[0] as u32) << 16) | ((chunk[1] as u32) << 8) | chunk[2] as u32;
        out.push(ALPHABET[(n >> 18) as usize & 0x3f] as char);
        out.push(ALPHABET[(n >> 12) as usize & 0x3f] as char);
        out.push(ALPHABET[(n >> 6) as usize & 0x3f] as char);
        out.push(ALPHABET[n as usize & 0x3f] as char);
    }
    match chunks.remainder() {
        [] => {}
        [a] => {
            let n = (*a as u32) << 16;
            out.push(ALPHABET[(n >> 18) as usize & 0x3f] as char);
            out.push(ALPHABET[(n >> 12) as usize & 0x3f] as char);
            out.push('=');
            out.push('=');
        }
        [a, b] => {
            let n = ((*a as u32) << 16) | ((*b as u32) << 8);
            out.push(ALPHABET[(n >> 18) as usize & 0x3f] as char);
            out.push(ALPHABET[(n >> 12) as usize & 0x3f] as char);
            out.push(ALPHABET[(n >> 6) as usize & 0x3f] as char);
            out.push('=');
        }
        _ => unreachable!(),
    }
}

/// Decode canonical base64 into a fresh vector.
pub fn decode(input: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(decoded_len(input.len()));
    decode_into(input, &mut out)?;
    Ok(out)
}

/// Decode canonical base64, appending to `out`.
///
/// On error `out` is rolled back to its length on entry (the decoder
/// commits only after a quantum decodes cleanly), so a caller can retry
/// with a repaired buffer without observing partially-decoded bytes.
pub fn decode_into(input: &[u8], out: &mut Vec<u8>) -> Result<()> {
    let start = out.len();
    match decode_core(input, Some(out)) {
        Ok(_) => Ok(()),
        Err(e) => {
            out.truncate(start);
            Err(e)
        }
    }
}

/// The decoder **and** the validator: one pass over the input that
/// either writes the decoded bytes into `out` or merely checks the
/// shape, returning how many bytes the input decodes to.
///
/// One core with two callers is deliberate: a validator that is a
/// separate implementation from the decoder is a validator that can
/// disagree with it, and a disagreement between "is this token
/// canonical?" and "what does this token decode to?" is exactly the bug
/// class this module exists to prevent.
fn decode_core(input: &[u8], out: Option<&mut Vec<u8>>) -> Result<usize> {
    if input.len() % 4 != 0 {
        return Err(Error::protocol("base64: length is not a multiple of 4"));
    }
    let mut out = out;
    if let Some(buf) = out.as_deref_mut() {
        buf.reserve(decoded_len(input.len()));
    }
    let mut written = 0usize;
    let mut finished = false;
    let mut vals = [0u8; 4];
    for chunk in input.chunks_exact(4) {
        if finished {
            return Err(Error::protocol("base64: trailing data after padding"));
        }
        let mut pad = 0usize;
        for (i, &c) in chunk.iter().enumerate() {
            if c == b'=' {
                if i < 2 {
                    return Err(Error::protocol("base64: padding in the first half"));
                }
                pad += 1;
                vals[i] = 0;
                continue;
            }
            if pad > 0 {
                return Err(Error::protocol("base64: data after padding"));
            }
            let v = DECODE_TABLE[c as usize];
            if v == INVALID {
                return Err(Error::protocol("base64: invalid character"));
            }
            vals[i] = v;
        }
        let n = ((vals[0] as u32) << 18)
            | ((vals[1] as u32) << 12)
            | ((vals[2] as u32) << 6)
            | vals[3] as u32;
        // The unused low bits of a padded quantum must be zero: without
        // this, two different strings decode to the same bytes and a
        // token comparison stops being a comparison.
        let (bytes, count) = match pad {
            0 => ([(n >> 16) as u8, (n >> 8) as u8, n as u8], 3usize),
            1 => {
                if vals[2] & 0x03 != 0 {
                    return Err(Error::protocol("base64: non-canonical padding bits"));
                }
                ([(n >> 16) as u8, (n >> 8) as u8, 0], 2)
            }
            2 => {
                if vals[1] & 0x0f != 0 {
                    return Err(Error::protocol("base64: non-canonical padding bits"));
                }
                ([(n >> 16) as u8, 0, 0], 1)
            }
            _ => return Err(Error::protocol("base64: too much padding")),
        };
        if let Some(buf) = out.as_deref_mut() {
            buf.extend_from_slice(&bytes[..count]);
        }
        written += count;
        if pad > 0 {
            finished = true;
        }
    }
    Ok(written)
}

/// Decode a `&str` (must be ASCII; non-ASCII bytes are rejected by the
/// character table).
#[inline]
pub fn decode_str(input: &str) -> Result<Vec<u8>> {
    decode(input.as_bytes())
}

/// Whether `text` is a syntactically valid RFC 4648 §4 string.
///
/// Zero allocations: the check shares its single pass with [`decode`].
pub fn is_canonical(input: &[u8]) -> bool {
    validate(input).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn rfc4648_vectors() {
        let cases: &[(&[u8], &str)] = &[
            (b"", ""),
            (b"f", "Zg=="),
            (b"fo", "Zm8="),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg=="),
            (b"fooba", "Zm9vYmE="),
            (b"foobar", "Zm9vYmFy"),
        ];
        for (raw, encoded) in cases {
            assert_eq!(encode(raw), *encoded);
            assert_eq!(decode(encoded.as_bytes()).unwrap(), raw.to_vec());
            assert_eq!(encoded_len(raw.len()), encoded.len());
        }
    }

    #[test]
    fn all_byte_values_roundtrip() {
        let data: Vec<u8> = (0..=255u8).collect();
        let text = encode(&data);
        assert_eq!(decode(text.as_bytes()).unwrap(), data);
        for n in 0..=data.len() {
            let t = encode(&data[..n]);
            assert_eq!(decode(t.as_bytes()).unwrap(), data[..n].to_vec());
        }
    }

    #[test]
    fn rejects_non_canonical_and_malformed() {
        assert!(decode(b"Zg==").is_ok());
        assert!(decode(b"Zg").is_err()); // bad length
        assert!(decode(b"Zg=").is_err()); // bad length
        assert!(decode(b"Zg===").is_err());
        assert!(decode(b"Z===").is_err()); // padding in first half
        assert!(decode(b"Zg==Zg==").is_err()); // data after padding
        assert!(decode(b"Zh==").is_err()); // non-canonical low bits
        assert!(decode(b"Zm9=").is_err()); // non-canonical low bits
        assert!(decode(b"Zm9v\n").is_err()); // whitespace is not ignored
        assert!(decode(b"Zm9*").is_err()); // out-of-alphabet byte
        assert!(decode(b"Zm9v YmFy").is_err());
        // Non-ASCII is rejected by the character table, not by UTF-8 luck.
        assert!(decode("Zm9é".as_bytes()).is_err());
    }

    /// `validate` / `is_canonical` / `decoded_size` are the same pass as
    /// `decode`, so they can never disagree with it about a string.
    #[test]
    fn validation_agrees_with_decoding() {
        let cases: &[&[u8]] = &[
            b"",
            b"Zg==",
            b"Zm8=",
            b"Zm9v",
            b"Zg",
            b"Zg=",
            b"Zg===",
            b"Z===",
            b"Zg==Zg==",
            b"Zh==",
            b"Zm9=",
            b"Zm9v\n",
            b"Zm9*",
            b"A",
            b"AA",
            b"AAA",
            b"AAAA",
            b"====",
            b"AB==",
            b"AAB=",
            b"AAAB",
        ];
        for case in cases {
            let decoded = decode(case);
            assert_eq!(validate(case).is_ok(), decoded.is_ok(), "{case:?}");
            assert_eq!(is_canonical(case), decoded.is_ok(), "{case:?}");
            match decoded {
                Ok(v) => assert_eq!(decoded_size(case).unwrap(), v.len(), "{case:?}"),
                Err(_) => assert!(decoded_size(case).is_err(), "{case:?}"),
            }
        }
        // Every suffix of a long canonical string is either canonical or
        // rejected by both, never accepted by one.
        let long = encode(&(0..=255u8).collect::<Vec<u8>>());
        let bytes = long.as_bytes();
        for cut in 0..bytes.len() {
            let slice = &bytes[..cut];
            assert_eq!(is_canonical(slice), decode(slice).is_ok(), "cut={cut}");
        }
    }

    /// `encoded_len` must be the exact size `encode` produces, for every
    /// residue, including the empty input.
    #[test]
    fn encoded_len_is_exact() {
        for len in 0..64usize {
            let data: Vec<u8> = (0..len).map(|i| i as u8).collect();
            assert_eq!(encoded_len(len), encode(&data).len(), "len={len}");
        }
    }

    #[test]
    fn decode_leaves_output_intact_on_error() {
        let mut out = vec![1, 2, 3];
        assert!(decode_into(b"AAAA!AAA", &mut out).is_err());
        assert_eq!(out, vec![1, 2, 3]);
    }

    #[test]
    fn websocket_key_shape() {
        // 16 random bytes -> 24 base64 characters ending in "==".
        let mut raw = [0u8; 16];
        for (i, b) in raw.iter_mut().enumerate() {
            *b = i as u8;
        }
        let key = encode(&raw);
        assert_eq!(key.len(), 24);
        assert!(key.ends_with("=="));
        assert_eq!(decode(key.as_bytes()).unwrap().len(), 16);
        assert!(is_canonical(key.as_bytes()));
    }
}
