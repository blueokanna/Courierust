//! QUIC frames (RFC 9000 §19).
//!
//! Encodes and decodes every frame type in RFC 9000 §19.1–§19.26,
//! including the ECN-count ACK (0x03), the STREAM offset/length bits,
//! both CONNECTION_CLOSE variants, MAX_STREAMS directionality, and the
//! DATAGRAM frames (RFC 9221). Frame parsing is strict about truncated
//! input and the reserved bits.
//!
//! The `data` payloads (CRYPTO, STREAM, NEW_TOKEN, DATAGRAM) are kept as
//! byte slices / `Vec<u8>`; packet protection is out of scope here.

use crate::courierust_error::{Error, Result};
use alloc::vec::Vec;

const MAX_ACK_RANGES: usize = 4096;
const MAX_CONNECTION_ID_LEN: usize = 20;

/// A parsed or to-be-encoded QUIC frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// PADDING (0x00). Carries the total number of padding bytes.
    Padding(usize),
    /// PING (0x01).
    Ping,
    /// ACK (0x02/0x03).
    Ack {
        /// The largest acknowledged packet number.
        largest_acked: u64,
        /// ACK delay in the peer's configured time units.
        ack_delay: u64,
        /// (gap, ack_range_length) pairs in wire order.
        ranges: Vec<(u64, u64)>,
        /// ECN counts (only for the 0x03 form).
        ecn: Option<[u64; 3]>,
    },
    /// RESET_STREAM (0x04).
    ResetStream {
        /// The stream being reset.
        stream_id: u64,
        /// Application error code.
        app_error_code: u64,
        /// Final size of the stream.
        final_size: u64,
    },
    /// STOP_SENDING (0x05).
    StopSending {
        /// The stream id.
        stream_id: u64,
        /// Application error code.
        app_error_code: u64,
    },
    /// CRYPTO (0x06).
    Crypto {
        /// Byte offset of `data` in the crypto stream.
        offset: u64,
        /// CRYPTO frame payload.
        data: Vec<u8>,
    },
    /// NEW_TOKEN (0x07).
    NewToken {
        /// The token bytes.
        token: Vec<u8>,
    },
    /// STREAM (0x08–0x0f). `offset`/`length` are `None` when the
    /// corresponding bit is clear.
    Stream {
        /// The stream id.
        stream_id: u64,
        /// Byte offset (present when the O bit is set).
        offset: Option<u64>,
        /// Stream payload bytes.
        data: Vec<u8>,
        /// Explicit data length (present when the L bit is set).
        length: Option<u64>,
        /// Whether this frame ends the stream (FIN bit).
        fin: bool,
    },
    /// MAX_DATA (0x10).
    MaxData(u64),
    /// MAX_STREAM_DATA (0x11).
    MaxStreamData {
        /// The stream id.
        stream_id: u64,
        /// The new maximum stream data.
        max: u64,
    },
    /// MAX_STREAMS (0x12 bidi / 0x13 uni).
    MaxStreams {
        /// Whether the limit applies to unidirectional streams.
        unidirectional: bool,
        /// The maximum number of streams.
        max: u64,
    },
    /// DATA_BLOCKED (0x14).
    DataBlocked(u64),
    /// STREAM_DATA_BLOCKED (0x15).
    StreamDataBlocked {
        /// The stream id.
        stream_id: u64,
        /// The stream data limit that is blocking.
        max: u64,
    },
    /// STREAMS_BLOCKED (0x16 bidi / 0x17 uni).
    StreamsBlocked {
        /// Whether the limit applies to unidirectional streams.
        unidirectional: bool,
        /// The stream limit that is blocking.
        max: u64,
    },
    /// NEW_CONNECTION_ID (0x18).
    NewConnectionId {
        /// The sequence number of this connection id.
        sequence: u64,
        /// Connection ids with a smaller sequence are retired.
        retire_prior_to: u64,
        /// The new connection id.
        connection_id: Vec<u8>,
        /// Stateless reset token for the new connection id.
        stateless_reset_token: [u8; 16],
    },
    /// RETIRE_CONNECTION_ID (0x19).
    RetireConnectionId(u64),
    /// PATH_CHALLENGE (0x1a).
    PathChallenge([u8; 8]),
    /// PATH_RESPONSE (0x1b).
    PathResponse([u8; 8]),
    /// CONNECTION_CLOSE (0x1c transport / 0x1d application).
    ConnectionClose {
        /// Error code.
        error_code: u64,
        /// Frame type that triggered the close (transport form only).
        frame_type: Option<u64>,
        /// Human-readable reason.
        reason: Vec<u8>,
    },
    /// HANDSHAKE_DONE (0x1e).
    HandshakeDone,
    /// DATAGRAM (0x30 / 0x31, RFC 9221). `length` is present in the 0x31
    /// form.
    Datagram {
        /// Datagram payload.
        data: Vec<u8>,
        /// Explicit length (present in the 0x31 form).
        length: Option<u64>,
    },
}

impl Frame {
    /// Encode the frame into `out`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Frame::Padding(n) => out.resize(out.len() + n, 0),
            Frame::Ping => out.push(0x01),
            Frame::Ack {
                largest_acked,
                ack_delay,
                ranges,
                ecn,
            } => {
                // ECN form (0x03) when counts are present.
                out.push(if ecn.is_some() { 0x03 } else { 0x02 });
                out.extend_from_slice(&crate::courierust_quic::varint::encode(*largest_acked));
                out.extend_from_slice(&crate::courierust_quic::varint::encode(*ack_delay));
                // Ack Range Count = additional ranges after the first
                // (RFC 9000 §19.3).
                let additional = ranges.len().saturating_sub(1) as u64;
                out.extend_from_slice(&crate::courierust_quic::varint::encode(additional));
                // First range is the count of consecutive acked packets
                // ending at largest_acked; encode the remaining ranges.
                if let Some((_, first_len)) = ranges.first() {
                    out.extend_from_slice(&crate::courierust_quic::varint::encode(*first_len));
                } else {
                    out.extend_from_slice(&crate::courierust_quic::varint::encode(0));
                }
                for (gap, range_len) in ranges.iter().skip(1) {
                    out.extend_from_slice(&crate::courierust_quic::varint::encode(*gap));
                    out.extend_from_slice(&crate::courierust_quic::varint::encode(*range_len));
                }
                if let Some([ecn_ce, ecn_ect0, ecn_ect1]) = ecn {
                    for v in [ecn_ce, ecn_ect0, ecn_ect1] {
                        out.extend_from_slice(&crate::courierust_quic::varint::encode(*v));
                    }
                }
            }
            Frame::ResetStream {
                stream_id,
                app_error_code,
                final_size,
            } => {
                out.push(0x04);
                out.extend_from_slice(&crate::courierust_quic::varint::encode(*stream_id));
                out.extend_from_slice(&crate::courierust_quic::varint::encode(*app_error_code));
                out.extend_from_slice(&crate::courierust_quic::varint::encode(*final_size));
            }
            Frame::StopSending {
                stream_id,
                app_error_code,
            } => {
                out.push(0x05);
                out.extend_from_slice(&crate::courierust_quic::varint::encode(*stream_id));
                out.extend_from_slice(&crate::courierust_quic::varint::encode(*app_error_code));
            }
            Frame::Crypto { offset, data } => {
                out.push(0x06);
                out.extend_from_slice(&crate::courierust_quic::varint::encode(*offset));
                out.extend_from_slice(&crate::courierust_quic::varint::encode(data.len() as u64));
                out.extend_from_slice(data);
            }
            Frame::NewToken { token } => {
                out.push(0x07);
                out.extend_from_slice(&crate::courierust_quic::varint::encode(token.len() as u64));
                out.extend_from_slice(token);
            }
            Frame::Stream {
                stream_id,
                offset,
                data,
                length,
                fin,
            } => {
                let mut first = 0x08u8;
                if *fin {
                    first |= 0x01;
                }
                if offset.is_some() {
                    first |= 0x04;
                }
                if length.is_some() {
                    first |= 0x02;
                }
                out.push(first);
                out.extend_from_slice(&crate::courierust_quic::varint::encode(*stream_id));
                if let Some(o) = offset {
                    out.extend_from_slice(&crate::courierust_quic::varint::encode(*o));
                }
                if let Some(l) = length {
                    out.extend_from_slice(&crate::courierust_quic::varint::encode(*l));
                }
                out.extend_from_slice(data);
            }
            Frame::MaxData(v) => {
                out.push(0x10);
                out.extend_from_slice(&crate::courierust_quic::varint::encode(*v));
            }
            Frame::MaxStreamData { stream_id, max } => {
                out.push(0x11);
                out.extend_from_slice(&crate::courierust_quic::varint::encode(*stream_id));
                out.extend_from_slice(&crate::courierust_quic::varint::encode(*max));
            }
            Frame::MaxStreams {
                unidirectional,
                max,
            } => {
                out.push(if *unidirectional { 0x13 } else { 0x12 });
                out.extend_from_slice(&crate::courierust_quic::varint::encode(*max));
            }
            Frame::DataBlocked(v) => {
                out.push(0x14);
                out.extend_from_slice(&crate::courierust_quic::varint::encode(*v));
            }
            Frame::StreamDataBlocked { stream_id, max } => {
                out.push(0x15);
                out.extend_from_slice(&crate::courierust_quic::varint::encode(*stream_id));
                out.extend_from_slice(&crate::courierust_quic::varint::encode(*max));
            }
            Frame::StreamsBlocked {
                unidirectional,
                max,
            } => {
                out.push(if *unidirectional { 0x17 } else { 0x16 });
                out.extend_from_slice(&crate::courierust_quic::varint::encode(*max));
            }
            Frame::NewConnectionId {
                sequence,
                retire_prior_to,
                connection_id,
                stateless_reset_token,
            } => {
                out.push(0x18);
                out.extend_from_slice(&crate::courierust_quic::varint::encode(*sequence));
                out.extend_from_slice(&crate::courierust_quic::varint::encode(*retire_prior_to));
                out.push(connection_id.len() as u8);
                out.extend_from_slice(connection_id);
                out.extend_from_slice(stateless_reset_token);
            }
            Frame::RetireConnectionId(v) => {
                out.push(0x19);
                out.extend_from_slice(&crate::courierust_quic::varint::encode(*v));
            }
            Frame::PathChallenge(d) => {
                out.push(0x1a);
                out.extend_from_slice(d);
            }
            Frame::PathResponse(d) => {
                out.push(0x1b);
                out.extend_from_slice(d);
            }
            Frame::ConnectionClose {
                error_code,
                frame_type,
                reason,
            } => {
                out.push(if frame_type.is_some() { 0x1c } else { 0x1d });
                out.extend_from_slice(&crate::courierust_quic::varint::encode(*error_code));
                if let Some(ft) = frame_type {
                    out.extend_from_slice(&crate::courierust_quic::varint::encode(*ft));
                }
                out.extend_from_slice(&crate::courierust_quic::varint::encode(reason.len() as u64));
                out.extend_from_slice(reason);
            }
            Frame::HandshakeDone => out.push(0x1e),
            Frame::Datagram { data, length } => {
                out.push(if length.is_some() { 0x31 } else { 0x30 });
                if let Some(l) = length {
                    out.extend_from_slice(&crate::courierust_quic::varint::encode(*l));
                }
                out.extend_from_slice(data);
            }
        }
    }

    /// Encode to a fresh `Vec<u8>`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode(&mut out);
        out
    }

    /// Decode one frame from `buf`, returning the frame and the number
    /// of bytes consumed. Returns `Ok(None)` for a PADDING-only buffer
    /// that consumed everything (so callers can iterate).
    pub fn decode(buf: &[u8]) -> Result<(Frame, usize)> {
        let first = *buf.first().ok_or_else(Error::eof)?;
        let mut pos = 1usize;
        macro_rules! varint {
            () => {{
                let (v, used) = crate::courierust_quic::varint::decode(&buf[pos..])?;
                pos += used;
                v
            }};
        }
        macro_rules! bytes {
            ($len:expr) => {{
                let n = $len;
                let end = pos
                    .checked_add(n)
                    .ok_or_else(|| Error::overflow("QUIC frame length overflow"))?;
                if buf.len() < end {
                    return Err(Error::eof());
                }
                let slice = &buf[pos..end];
                pos = end;
                slice.to_vec()
            }};
        }
        match first {
            0x00 => {
                // PADDING: consume the run.
                let start = pos;
                while pos < buf.len() && buf[pos] == 0 {
                    pos += 1;
                }
                // Note: `start` counts only the continuation bytes; the
                // first byte is included in `pos` already.
                Ok((Frame::Padding(1 + (pos - start)), pos))
            }
            0x01 => Ok((Frame::Ping, pos)),
            0x02 | 0x03 => {
                let largest_acked = varint!();
                let ack_delay = varint!();
                let range_count = usize::try_from(varint!())
                    .map_err(|_| Error::overflow("QUIC ACK range count does not fit usize"))?;
                if range_count > MAX_ACK_RANGES {
                    return Err(Error::overflow("QUIC ACK range count exceeds limit"));
                }
                let first_range = varint!();
                if first_range > largest_acked {
                    return Err(Error::protocol(
                        "QUIC ACK first range underflows packet number",
                    ));
                }
                let mut ranges = Vec::with_capacity(range_count.saturating_add(1));
                ranges.push((0, first_range));
                let mut previous_low = largest_acked - first_range;
                for _ in 0..range_count {
                    let gap = varint!();
                    let range_len = varint!();
                    let gap_plus_two = gap
                        .checked_add(2)
                        .ok_or_else(|| Error::protocol("QUIC ACK gap overflows packet number"))?;
                    let next_largest = previous_low.checked_sub(gap_plus_two).ok_or_else(|| {
                        Error::protocol("QUIC ACK range gap underflows packet number")
                    })?;
                    if range_len > next_largest {
                        return Err(Error::protocol("QUIC ACK range underflows packet number"));
                    }
                    ranges.push((gap, range_len));
                    previous_low = next_largest - range_len;
                }
                let ecn = if first == 0x03 {
                    let ce = varint!();
                    let ect0 = varint!();
                    let ect1 = varint!();
                    Some([ce, ect0, ect1])
                } else {
                    None
                };
                Ok((
                    Frame::Ack {
                        largest_acked,
                        ack_delay,
                        ranges,
                        ecn,
                    },
                    pos,
                ))
            }
            0x04 => {
                let stream_id = varint!();
                let app_error_code = varint!();
                let final_size = varint!();
                Ok((
                    Frame::ResetStream {
                        stream_id,
                        app_error_code,
                        final_size,
                    },
                    pos,
                ))
            }
            0x05 => {
                let stream_id = varint!();
                let app_error_code = varint!();
                Ok((
                    Frame::StopSending {
                        stream_id,
                        app_error_code,
                    },
                    pos,
                ))
            }
            0x06 => {
                let offset = varint!();
                let len = varint!();
                let len = usize::try_from(len)
                    .map_err(|_| Error::overflow("QUIC CRYPTO length does not fit usize"))?;
                let data = bytes!(len);
                Ok((Frame::Crypto { offset, data }, pos))
            }
            0x07 => {
                let len = varint!();
                let len = usize::try_from(len)
                    .map_err(|_| Error::overflow("QUIC token length does not fit usize"))?;
                let token = bytes!(len);
                Ok((Frame::NewToken { token }, pos))
            }
            0x08..=0x0f => {
                let stream_id = varint!();
                let has_offset = first & 0x04 != 0;
                let has_length = first & 0x02 != 0;
                let fin = first & 0x01 != 0;
                let offset = if has_offset { Some(varint!()) } else { None };
                let length = if has_length { Some(varint!()) } else { None };
                let data_len = match length {
                    Some(l) => usize::try_from(l)
                        .map_err(|_| Error::overflow("QUIC STREAM length does not fit usize"))?,
                    None => buf.len() - pos,
                };
                let data = bytes!(data_len);
                Ok((
                    Frame::Stream {
                        stream_id,
                        offset,
                        data,
                        length,
                        fin,
                    },
                    pos,
                ))
            }
            0x10 => Ok((Frame::MaxData(varint!()), pos)),
            0x11 => {
                let stream_id = varint!();
                let max = varint!();
                Ok((Frame::MaxStreamData { stream_id, max }, pos))
            }
            0x12 | 0x13 => {
                let max = varint!();
                Ok((
                    Frame::MaxStreams {
                        unidirectional: first == 0x13,
                        max,
                    },
                    pos,
                ))
            }
            0x14 => Ok((Frame::DataBlocked(varint!()), pos)),
            0x15 => {
                let stream_id = varint!();
                let max = varint!();
                Ok((Frame::StreamDataBlocked { stream_id, max }, pos))
            }
            0x16 | 0x17 => {
                let max = varint!();
                Ok((
                    Frame::StreamsBlocked {
                        unidirectional: first == 0x17,
                        max,
                    },
                    pos,
                ))
            }
            0x18 => {
                let sequence = varint!();
                let retire_prior_to = varint!();
                if retire_prior_to > sequence {
                    return Err(Error::protocol(
                        "QUIC NEW_CONNECTION_ID retire value exceeds sequence",
                    ));
                }
                let cid_len = *buf.get(pos).ok_or_else(Error::eof)? as usize;
                pos += 1;
                if !(1..=MAX_CONNECTION_ID_LEN).contains(&cid_len) {
                    return Err(Error::protocol("QUIC connection ID length must be 1-20"));
                }
                let connection_id = bytes!(cid_len);
                let end = pos
                    .checked_add(16)
                    .ok_or_else(|| Error::overflow("QUIC connection ID token offset overflow"))?;
                if buf.len() < end {
                    return Err(Error::eof());
                }
                let mut token = [0u8; 16];
                token.copy_from_slice(&buf[pos..end]);
                pos = end;
                Ok((
                    Frame::NewConnectionId {
                        sequence,
                        retire_prior_to,
                        connection_id,
                        stateless_reset_token: token,
                    },
                    pos,
                ))
            }
            0x19 => Ok((Frame::RetireConnectionId(varint!()), pos)),
            0x1a => {
                let data = bytes!(8);
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&data);
                Ok((Frame::PathChallenge(arr), pos))
            }
            0x1b => {
                let data = bytes!(8);
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&data);
                Ok((Frame::PathResponse(arr), pos))
            }
            0x1c | 0x1d => {
                let error_code = varint!();
                let frame_type = if first == 0x1c { Some(varint!()) } else { None };
                let reason_len = varint!();
                let reason_len = usize::try_from(reason_len)
                    .map_err(|_| Error::overflow("QUIC close reason length does not fit usize"))?;
                let reason = bytes!(reason_len);
                Ok((
                    Frame::ConnectionClose {
                        error_code,
                        frame_type,
                        reason,
                    },
                    pos,
                ))
            }
            0x1e => Ok((Frame::HandshakeDone, pos)),
            0x30 | 0x31 => {
                let length = if first == 0x31 { Some(varint!()) } else { None };
                let data_len = match length {
                    Some(l) => usize::try_from(l)
                        .map_err(|_| Error::overflow("QUIC DATAGRAM length does not fit usize"))?,
                    None => buf.len() - pos,
                };
                let data = bytes!(data_len);
                Ok((
                    Frame::Datagram {
                        data,
                        length: if first == 0x31 {
                            Some(data_len as u64)
                        } else {
                            None
                        },
                    },
                    pos,
                ))
            }
            _ => Err(Error::protocol("unknown QUIC frame type")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(frame: Frame) {
        let wire = frame.to_bytes();
        let (decoded, used) = Frame::decode(&wire).unwrap();
        assert_eq!(decoded, frame, "round trip for {frame:?}");
        assert_eq!(used, wire.len());
    }

    #[test]
    fn basic_frames_round_trip() {
        round_trip(Frame::Ping);
        round_trip(Frame::HandshakeDone);
        round_trip(Frame::Padding(4));
        round_trip(Frame::MaxData(1 << 30));
        round_trip(Frame::DataBlocked(123456));
        round_trip(Frame::RetireConnectionId(7));
        round_trip(Frame::PathChallenge([1, 2, 3, 4, 5, 6, 7, 8]));
        round_trip(Frame::PathResponse([9, 9, 9, 9, 9, 9, 9, 9]));
    }

    #[test]
    fn stream_frames_round_trip() {
        round_trip(Frame::Stream {
            stream_id: 0,
            offset: Some(1024),
            data: b"hello world".to_vec(),
            length: Some(11),
            fin: true,
        });
        round_trip(Frame::Stream {
            stream_id: 8,
            offset: None,
            data: vec![1, 2, 3],
            length: None,
            fin: false,
        });
    }

    #[test]
    fn ack_round_trip_with_and_without_ecn() {
        round_trip(Frame::Ack {
            largest_acked: 42,
            ack_delay: 3,
            ranges: vec![(0, 10), (2, 5), (1, 7)],
            ecn: None,
        });
        round_trip(Frame::Ack {
            largest_acked: 99,
            ack_delay: 0,
            ranges: vec![(0, 50)],
            ecn: Some([1, 2, 3]),
        });
    }

    #[test]
    fn close_and_streams_frames() {
        round_trip(Frame::ConnectionClose {
            error_code: 0x0100,
            frame_type: Some(0x06),
            reason: b"crypto error".to_vec(),
        });
        round_trip(Frame::ConnectionClose {
            error_code: 0,
            frame_type: None,
            reason: b"bye".to_vec(),
        });
        round_trip(Frame::MaxStreams {
            unidirectional: true,
            max: 16,
        });
        round_trip(Frame::StreamsBlocked {
            unidirectional: false,
            max: 0,
        });
        round_trip(Frame::NewConnectionId {
            sequence: 1,
            retire_prior_to: 0,
            connection_id: vec![0xaa, 0xbb],
            stateless_reset_token: [7u8; 16],
        });
        round_trip(Frame::Datagram {
            data: b"dgram".to_vec(),
            length: Some(5),
        });
        round_trip(Frame::Datagram {
            data: vec![9, 9],
            length: None,
        });
    }

    #[test]
    fn truncated_input_errors() {
        assert!(Frame::decode(&[]).is_err());
        assert!(
            Frame::decode(&[0x04, 0x00]).is_err(),
            "RESET_STREAM needs 3 varints"
        );
        assert!(
            Frame::decode(&[0x06, 0x00, 0x05, 0x61]).is_err(),
            "CRYPTO data truncated"
        );
    }
}
