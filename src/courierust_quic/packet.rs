//! QUIC packet headers and packet numbers (RFC 9000 §17).
//!
//! Encodes/decodes the *cleartext* parts of a QUIC packet: the long or
//! short header, connection id, packet number and the packet-number
//! encoding (RFC 9000 §17.1). Header protection and AEAD are out of
//! is provided by [`crate::courierust_quic::protection`] for the `std`
//! runtime (see the module docs in `courierust_quic`).

use crate::courierust_error::{Error, Result};
use alloc::vec::Vec;

const MAX_CONNECTION_ID_LEN: usize = 20;

/// Long-header packet types (RFC 9000 §17.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LongType {
    /// Initial (0x00).
    Initial = 0x00,
    /// 0-RTT (0x01).
    ZeroRtt = 0x01,
    /// Handshake (0x02).
    Handshake = 0x02,
    /// Retry (0x03).
    Retry = 0x03,
}

impl LongType {
    /// The 2-bit wire value.
    pub fn wire(self) -> u8 {
        self as u8
    }
}

/// A parsed long-header packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LongHeader {
    /// Packet type.
    pub packet_type: LongType,
    /// Destination connection id.
    pub dcid: Vec<u8>,
    /// Source connection id.
    pub scid: Vec<u8>,
    /// Packet number (already un-protected for the handshake/1-RTT
    /// layers that call this codec).
    pub packet_number: u64,
    /// The packet number length field (0–3 → 1–4 bytes).
    pub pn_len: usize,
}

/// A parsed short-header packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShortHeader {
    /// Destination connection id.
    pub dcid: Vec<u8>,
    /// Packet number.
    pub packet_number: u64,
    /// The packet number length field.
    pub pn_len: usize,
}

/// Write a long header. `token` and `length` cover the Initial-specific
/// fields; other long types pass empty/`0`.
pub fn encode_long(
    packet_type: LongType,
    dcid: &[u8],
    scid: &[u8],
    pn: u64,
    pn_len: usize,
    token: &[u8],
    payload_len: u64,
) -> Result<Vec<u8>> {
    let pn_len_field = pn_len_byte(pn_len)?;
    if dcid.len() > MAX_CONNECTION_ID_LEN || scid.len() > MAX_CONNECTION_ID_LEN {
        return Err(Error::protocol(
            "QUIC connection ID must be at most 20 bytes",
        ));
    }
    if token.len() as u64 > crate::courierust_quic::varint::MAX {
        return Err(Error::overflow("QUIC token length exceeds varint range"));
    }
    if payload_len > crate::courierust_quic::varint::MAX || payload_len < pn_len as u64 {
        return Err(Error::protocol("invalid QUIC long-header payload length"));
    }
    let mut out = Vec::with_capacity(1 + 4 + 1 + 1 + dcid.len() + scid.len() + token.len() + 8);
    out.push(0xc0 | (packet_type.wire() << 4) | pn_len_field);
    out.extend_from_slice(&crate::courierust_quic::VERSION_1.to_be_bytes());
    out.push(dcid.len() as u8);
    out.extend_from_slice(dcid);
    out.push(scid.len() as u8);
    out.extend_from_slice(scid);
    if packet_type == LongType::Initial {
        out.extend_from_slice(&crate::courierust_quic::varint::encode(token.len() as u64));
        out.extend_from_slice(token);
    }
    out.extend_from_slice(&crate::courierust_quic::varint::encode(payload_len));
    out.extend_from_slice(&encode_pn(pn, pn_len)?);
    Ok(out)
}

/// Write a short header.
pub fn encode_short(dcid: &[u8], pn: u64, pn_len: usize, key_phase: bool) -> Result<Vec<u8>> {
    let pn_len_field = pn_len_byte(pn_len)?;
    if dcid.len() > MAX_CONNECTION_ID_LEN {
        return Err(Error::protocol(
            "QUIC connection ID must be at most 20 bytes",
        ));
    }
    let mut out = Vec::with_capacity(1 + dcid.len() + pn_len);
    // Short header (RFC 9000 §17.3.1): 0x40 fixed bit, key phase at
    // bit 2 (0x04), packet-number length in the low two bits. Bits 4-3
    // (0x18) are reserved and stay 0.
    out.push(0x40 | (u8::from(key_phase) << 2) | pn_len_field);
    out.extend_from_slice(dcid);
    out.extend_from_slice(&encode_pn(pn, pn_len)?);
    Ok(out)
}

/// Encode the packet number in `pn_len` bytes (RFC 9000 §17.1). The
/// truncated form used on the wire is the low `pn_len` bytes.
pub fn encode_pn(pn: u64, pn_len: usize) -> Result<Vec<u8>> {
    if !(1..=4).contains(&pn_len) {
        return Err(Error::protocol("packet number length must be 1-4"));
    }
    let mut out = Vec::with_capacity(pn_len);
    for shift in (0..pn_len).rev() {
        out.push((pn >> (shift * 8)) as u8);
    }
    Ok(out)
}

/// Recover the full packet number from its truncated wire form
/// (RFC 9000 §17.1, Appendix A.2).
pub fn decode_pn(truncated: &[u8], expected: u64, pn_len: usize) -> u64 {
    let bits = match pn_len {
        1 => 8u32,
        2 => 16,
        3 => 24,
        4 => 32,
        _ => return expected,
    };
    let mask = (1u64 << bits) - 1;
    let truncated_value = truncated
        .iter()
        .take(pn_len)
        .fold(0u64, |acc, &b| (acc << 8) | b as u64);
    let win = 1u64 << (bits - 1);
    let window = 1u64 << bits;
    let candidate = (expected & !mask) | truncated_value;
    if expected >= win && candidate <= expected - win {
        if let Some(next) = candidate.checked_add(window) {
            return next;
        }
    }
    if candidate > expected.saturating_add(win) && candidate >= window {
        candidate - window
    } else {
        candidate
    }
}

/// Parse a packet. Returns `Long(LongHeader)`, `Short(ShortHeader)`, or
/// an error for malformed input. `expected_pn` is used to recover the
/// full packet number from its truncated form.
pub fn parse(buf: &[u8], expected_pn: u64, local_cid_len: usize) -> Result<Packet> {
    let first = *buf.first().ok_or_else(Error::eof)?;
    if first & 0x80 != 0 {
        // Long header.
        if buf.len() < 7 {
            return Err(Error::eof());
        }
        let packet_type = match (first >> 4) & 0x03 {
            0 => LongType::Initial,
            1 => LongType::ZeroRtt,
            2 => LongType::Handshake,
            _ => LongType::Retry,
        };
        let version = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
        if version == 0 {
            return Err(Error::protocol(
                "version-negotiation packet is not parseable",
            ));
        }
        let dcid_len = buf[5] as usize;
        let mut pos: usize = 6;
        let dcid_end = pos
            .checked_add(dcid_len)
            .ok_or_else(|| Error::overflow("QUIC DCID offset overflow"))?;
        if dcid_len > MAX_CONNECTION_ID_LEN || dcid_end >= buf.len() {
            return Err(Error::eof());
        }
        let dcid = buf[pos..dcid_end].to_vec();
        pos = dcid_end;
        let scid_len = buf[pos] as usize;
        pos += 1;
        let scid_end = pos
            .checked_add(scid_len)
            .ok_or_else(|| Error::overflow("QUIC SCID offset overflow"))?;
        if scid_len > MAX_CONNECTION_ID_LEN || scid_end > buf.len() {
            return Err(Error::eof());
        }
        let scid = buf[pos..scid_end].to_vec();
        pos = scid_end;
        if packet_type == LongType::Retry {
            return Err(Error::protocol(
                "QUIC Retry packets require a dedicated parser",
            ));
        }
        // Initial carries a token + length.
        if packet_type == LongType::Initial {
            let (token_len, used) = crate::courierust_quic::varint::decode(&buf[pos..])?;
            pos = pos
                .checked_add(used)
                .ok_or_else(|| Error::overflow("QUIC token offset overflow"))?;
            let token_len = usize::try_from(token_len)
                .map_err(|_| Error::overflow("QUIC token length does not fit usize"))?;
            let token_end = pos
                .checked_add(token_len)
                .ok_or_else(|| Error::overflow("QUIC token length overflow"))?;
            if buf.len() < token_end {
                return Err(Error::eof());
            }
            pos = token_end;
        }
        let (payload_len, used) = crate::courierust_quic::varint::decode(&buf[pos..])?;
        pos = pos
            .checked_add(used)
            .ok_or_else(|| Error::overflow("QUIC payload offset overflow"))?;
        let pn_len = 1 + ((first & 0x03) as usize);
        if payload_len < pn_len as u64 {
            return Err(Error::protocol(
                "QUIC payload is shorter than packet number",
            ));
        }
        let packet_end = pos
            .checked_add(
                usize::try_from(payload_len)
                    .map_err(|_| Error::overflow("QUIC payload length does not fit usize"))?,
            )
            .ok_or_else(|| Error::overflow("QUIC packet length overflow"))?;
        let pn_end = pos
            .checked_add(pn_len)
            .ok_or_else(|| Error::overflow("QUIC packet-number offset overflow"))?;
        if buf.len() < packet_end || buf.len() < pn_end {
            return Err(Error::eof());
        }
        let pn = decode_pn(&buf[pos..pn_end], expected_pn, pn_len);
        let _ = payload_len;
        Ok(Packet::Long(LongHeader {
            packet_type,
            dcid,
            scid,
            packet_number: pn,
            pn_len,
        }))
    } else {
        // Short header.
        if local_cid_len > MAX_CONNECTION_ID_LEN {
            return Err(Error::protocol(
                "QUIC connection ID must be at most 20 bytes",
            ));
        }
        let start = 1usize
            .checked_add(local_cid_len)
            .ok_or_else(|| Error::overflow("QUIC short-header offset overflow"))?;
        if buf.len() < start + 1 {
            return Err(Error::eof());
        }
        let dcid = buf[1..start].to_vec();
        let pn_len = 1 + ((first & 0x03) as usize);
        if buf.len() < start + pn_len {
            return Err(Error::eof());
        }
        let pn = decode_pn(&buf[start..start + pn_len], expected_pn, pn_len);
        Ok(Packet::Short(ShortHeader {
            dcid,
            packet_number: pn,
            pn_len,
        }))
    }
}

/// A parsed packet header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Packet {
    /// Long-header packet.
    Long(LongHeader),
    /// Short-header packet.
    Short(ShortHeader),
}

/// Map a 2-bit length field to a byte count (1–4).
fn pn_len_byte(pn_len: usize) -> Result<u8> {
    match pn_len {
        1 => Ok(0),
        2 => Ok(1),
        3 => Ok(2),
        4 => Ok(3),
        _ => Err(Error::protocol("packet number length must be 1-4")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_header_round_trip() {
        let mut wire = encode_long(
            LongType::Handshake,
            &[1, 2, 3, 4],
            &[5, 6, 7, 8],
            12345,
            2,
            &[],
            100,
        )
        .unwrap();
        // `encode_long` emits the header and packet number. The declared
        // payload length still has to be present on the wire.
        wire.extend_from_slice(&[0u8; 98]);
        let parsed = parse(&wire, 12000, 0).unwrap();
        match parsed {
            Packet::Long(h) => {
                assert_eq!(h.packet_type, LongType::Handshake);
                assert_eq!(h.dcid, vec![1, 2, 3, 4]);
                assert_eq!(h.scid, vec![5, 6, 7, 8]);
                assert_eq!(h.packet_number, 12345);
                assert_eq!(h.pn_len, 2);
            }
            Packet::Short(_) => panic!("expected long header"),
        }
    }

    #[test]
    fn short_header_round_trip() {
        let wire = encode_short(&[9, 9, 9], 777, 3, false).unwrap();
        let parsed = parse(&wire, 700, 3).unwrap();
        match parsed {
            Packet::Short(h) => {
                assert_eq!(h.dcid, vec![9, 9, 9]);
                assert_eq!(h.packet_number, 777);
                assert_eq!(h.pn_len, 3);
            }
            Packet::Long(_) => panic!("expected short header"),
        }
    }

    #[test]
    fn pn_recovery_appendix_a2() {
        // RFC 9000 Appendix A.2 example: expected 0xac5c02 (11295916642
        // mod 2^24 is 0x5c02 truncated... use the worked values).
        // Truncated = 0x5c02, expected full = 0x0aac5c02, pn_len = 2.
        let full = decode_pn(&[0x5c, 0x02], 0x0aac_5c02, 2);
        // RFC: with expected 0xa82f30ea (near) and truncated 0x9b32, the
        // recovered full number is 0xa82f9b32.
        let recovered = decode_pn(&[0x9b, 0x32], 0xa82f_30ea, 2);
        assert_eq!(recovered, 0xa82f_9b32, "RFC 9000 Appendix A.2 case 3");
        assert_eq!(full & 0xffff, 0x5c02);
    }

    #[test]
    fn malformed_rejected() {
        assert!(parse(&[], 0, 0).is_err());
        assert!(parse(&[0xc0, 0, 0, 0, 0], 0, 0).is_err());
        // Version-negotiation packet is not parseable as a normal packet.
        assert!(parse(&[0xc0, 0, 0, 0, 0, 0, 0], 0, 0).is_err());
    }
}
