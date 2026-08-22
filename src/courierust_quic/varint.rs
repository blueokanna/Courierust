//! QUIC variable-length integers (RFC 9000 §16).
//!
//! A QUIC varint is 1–8 bytes. The two most significant bits of the
//! first byte encode the length: `00` → 6-bit value in 1 byte, `01` →
//! 14-bit value in 2 bytes, `10` → 30-bit value in 4 bytes, `11` →
//! 62-bit value in 8 bytes. All values are big-endian within their
//! reserved length.

use crate::courierust_error::{Error, Result};
use alloc::vec::Vec;

/// The largest value a varint can carry (2^62 − 1).
pub const MAX: u64 = (1 << 62) - 1;

/// Encode `value` as a QUIC varint.
///
/// Panics if `value` exceeds [`MAX`] (the caller must have validated it;
/// this matches how the other codecs treat programmer errors).
pub fn encode(value: u64) -> Vec<u8> {
    assert!(value <= MAX, "varint value {value} exceeds 2^62-1");
    if value < (1 << 6) {
        vec![value as u8]
    } else if value < (1 << 14) {
        vec![0x40 | ((value >> 8) as u8), (value & 0xff) as u8]
    } else if value < (1 << 30) {
        vec![
            0x80 | ((value >> 24) as u8),
            ((value >> 16) & 0xff) as u8,
            ((value >> 8) & 0xff) as u8,
            (value & 0xff) as u8,
        ]
    } else {
        let mut out = Vec::with_capacity(8);
        out.push(0xc0 | ((value >> 56) as u8));
        for shift in (0..56).step_by(8).rev() {
            out.push(((value >> shift) & 0xff) as u8);
        }
        out
    }
}

/// Decode one varint from `buf`. Returns the value and the number of
/// bytes consumed. Returns an error when `buf` is empty or too short for
/// the length indicated by the first byte.
pub fn decode(buf: &[u8]) -> Result<(u64, usize)> {
    let first = *buf.first().ok_or_else(Error::eof)?;
    let len = match first >> 6 {
        0 => 1,
        1 => 2,
        2 => 4,
        _ => 8,
    };
    if buf.len() < len {
        return Err(Error::eof());
    }
    let mut value: u64 = (first & 0x3f) as u64;
    for &byte in &buf[1..len] {
        value = (value << 8) | byte as u64;
    }
    Ok((value, len))
}

/// Decode one varint, returning only the value.
pub fn read(buf: &[u8]) -> Result<u64> {
    decode(buf).map(|(v, _)| v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_9000_section_16_examples() {
        // RFC 9000 §16.1 worked examples.
        assert_eq!(decode(&[0x00]).unwrap(), (0, 1));
        assert_eq!(decode(&[0x3f]).unwrap(), (63, 1));
        assert_eq!(decode(&[0x40, 0x25]).unwrap(), (37, 2));
        assert_eq!(decode(&[0x7f, 0xff]).unwrap(), (16383, 2));
        assert_eq!(decode(&[0x80, 0x00, 0x25, 0x00]).unwrap(), (9472, 4));
        assert_eq!(
            decode(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]).unwrap(),
            (4611686018427387903, 8)
        );
    }

    #[test]
    fn round_trip_all_widths() {
        for value in [
            0u64,
            1,
            62,
            63,
            64,
            16383,
            16384,
            (1 << 30) - 1,
            1 << 30,
            MAX,
        ] {
            let wire = encode(value);
            let (decoded, used) = decode(&wire).unwrap();
            assert_eq!(decoded, value, "value {value}");
            assert_eq!(used, wire.len(), "length for {value}");
        }
    }

    #[test]
    fn truncated_errors() {
        assert!(decode(&[]).is_err());
        // First byte claims a 2-byte varint but only one byte remains.
        assert!(decode(&[0x40]).is_err());
        assert!(decode(&[0x80, 0x00]).is_err());
        assert!(decode(&[0xc0, 0, 0, 0]).is_err());
    }
}
