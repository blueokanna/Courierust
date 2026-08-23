//! HTTP/3 frames, stream types and settings (RFC 9114 §6.2 / §7.2).
//!
//! HTTP/3 frames use a 2-byte (QUIC varint) length prefix and a QUIC
//! varint type. The frame stream types and SETTINGS identifiers are
//! defined here, as are the unidirectional stream roles (§6.2):
//! control (0x00), push (0x01), QPACK encoder (0x02), QPACK decoder
//! (0x03).

use crate::courierust_error::{Error, Result};
use alloc::string::ToString;
use alloc::vec::Vec;

const MAX_SETTINGS_ENTRIES: usize = 256;

/// Unidirectional stream types (RFC 9114 §6.2.1).
pub const STREAM_TYPE_CONTROL: u64 = 0x00;
/// Unidirectional stream type: push stream.
pub const STREAM_TYPE_PUSH: u64 = 0x01;
/// Unidirectional stream type: QPACK encoder stream.
pub const STREAM_TYPE_QPACK_ENCODER: u64 = 0x02;
/// Unidirectional stream type: QPACK decoder stream.
pub const STREAM_TYPE_QPACK_DECODER: u64 = 0x03;

/// SETTINGS identifiers (RFC 9114 §7.2.4.1).
pub const SETTINGS_QPACK_MAX_TABLE_CAPACITY: u64 = 0x1;
/// SETTINGS_MAX_FIELD_SECTION_SIZE (the maximum size of a header list
/// the peer is willing to accept).
pub const SETTINGS_MAX_FIELD_SECTION_SIZE: u64 = 0x6;
/// SETTINGS_QPACK_BLOCKED_STREAMS.
pub const SETTINGS_QPACK_BLOCKED_STREAMS: u64 = 0x7;
/// SETTINGS_ENABLE_CONNECT_PROTOCOL (RFC 8441).
pub const SETTINGS_ENABLE_CONNECT_PROTOCOL: u64 = 0x8;
/// SETTINGS_H3_DATAGRAM (RFC 9297).
pub const SETTINGS_H3_DATAGRAM: u64 = 0x33;
/// SETTINGS_ENABLE_WEBTRANSPORT (RFC 9220).
pub const SETTINGS_ENABLE_WEBTRANSPORT: u64 = 0x2b603742;
/// SETTINGS_WEBTRANSPORT_MAX_SESSIONS (RFC 9220).
pub const SETTINGS_WEBTRANSPORT_MAX_SESSIONS: u64 = 0x2b603743;
/// The legacy `SETTINGS_MAX_PUSH_ID` alias is not a real identifier;
/// push is bounded by MAX_PUSH_ID frames, not a SETTINGS entry.
/// An HTTP/3 frame (RFC 9114 §7.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// DATA (0x00) — request/response body bytes.
    Data(Vec<u8>),
    /// HEADERS (0x01) — a QPACK-encoded header section.
    Headers(Vec<u8>),
    /// CANCEL_PUSH (0x03) — the push id of a push to cancel.
    CancelPush(u64),
    /// SETTINGS (0x04) — identifier/value pairs.
    Settings(Vec<(u64, u64)>),
    /// PUSH_PROMISE (0x05) — the push id plus a QPACK header section.
    PushPromise {
        /// The push id.
        push_id: u64,
        /// The encoded field section.
        headers: Vec<u8>,
    },
    /// GOAWAY (0x07) — the last client-initiated request stream id.
    GoAway(u64),
    /// MAX_PUSH_ID (0x0d) - the largest push id the server may use.
    MaxPushId(u64),
    /// An extension frame. Unknown HTTP/3 frame types are ignored by the
    /// protocol; retaining the payload keeps the codec lossless.
    Unknown {
        /// Extension frame type.
        frame_type: u64,
        /// Extension payload.
        payload: Vec<u8>,
    },
}

impl Frame {
    /// The wire type value.
    pub fn frame_type(&self) -> u64 {
        match self {
            Frame::Data(_) => 0x00,
            Frame::Headers(_) => 0x01,
            Frame::CancelPush(_) => 0x03,
            Frame::Settings(_) => 0x04,
            Frame::PushPromise { .. } => 0x05,
            Frame::GoAway(_) => 0x07,
            Frame::MaxPushId(_) => 0x0d,
            Frame::Unknown { frame_type, .. } => *frame_type,
        }
    }

    /// Encode the frame (type + length + payload) into `out`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        let mut payload = Vec::new();
        match self {
            Frame::Data(d) => payload.extend_from_slice(d),
            Frame::Headers(h) => payload.extend_from_slice(h),
            Frame::CancelPush(id) => {
                crate::courierust_h3::qpack::encode_integer(*id, 8, 0, &mut payload);
            }
            Frame::Settings(settings) => {
                // RFC 9114 §7.2.4: SETTINGS identifiers and values are
                // QUIC variable-length integers (NOT QPACK prefix
                // integers, which only coincide for small values).
                for (id, value) in settings {
                    payload.extend_from_slice(&crate::courierust_quic::varint::encode(*id));
                    payload.extend_from_slice(&crate::courierust_quic::varint::encode(*value));
                }
            }
            Frame::PushPromise { push_id, headers } => {
                crate::courierust_h3::qpack::encode_integer(*push_id, 8, 0, &mut payload);
                payload.extend_from_slice(headers);
            }
            Frame::GoAway(id) => {
                crate::courierust_h3::qpack::encode_integer(*id, 8, 0, &mut payload);
            }
            Frame::MaxPushId(id) => {
                crate::courierust_h3::qpack::encode_integer(*id, 8, 0, &mut payload);
            }
            Frame::Unknown { payload: data, .. } => payload.extend_from_slice(data),
        }
        out.extend_from_slice(&crate::courierust_quic::varint::encode(self.frame_type()));
        out.extend_from_slice(&crate::courierust_quic::varint::encode(payload.len() as u64));
        out.extend_from_slice(&payload);
    }

    /// Encode to a fresh `Vec<u8>`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode(&mut out);
        out
    }

    /// Decode one frame from `buf` starting at `*pos`. Advances `*pos`
    /// past the whole frame. Returns `None` when the buffer holds only a
    /// partial frame (caller should wait for more data).
    pub fn decode(buf: &[u8], pos: &mut usize) -> Result<Option<Frame>> {
        if *pos > buf.len() {
            return Err(Error::protocol("HTTP/3 frame position is outside buffer"));
        }
        if *pos == buf.len() {
            return Ok(None);
        }
        let (frame_type, used) = match crate::courierust_quic::varint::decode(&buf[*pos..]) {
            Ok(value) => value,
            Err(error) if error.kind == crate::courierust_error::ErrorKind::UnexpectedEof => {
                return Ok(None)
            }
            Err(error) => return Err(error),
        };
        let mut p = (*pos)
            .checked_add(used)
            .ok_or_else(|| Error::overflow("HTTP/3 frame type offset overflow"))?;
        let (length, used) = match crate::courierust_quic::varint::decode(&buf[p..]) {
            Ok(value) => value,
            Err(error) if error.kind == crate::courierust_error::ErrorKind::UnexpectedEof => {
                return Ok(None)
            }
            Err(error) => return Err(error),
        };
        p = p
            .checked_add(used)
            .ok_or_else(|| Error::overflow("HTTP/3 frame payload offset overflow"))?;
        let length = usize::try_from(length)
            .map_err(|_| Error::overflow("HTTP/3 frame length does not fit usize"))?;
        let end = p
            .checked_add(length)
            .ok_or_else(|| Error::overflow("HTTP/3 frame length overflow"))?;
        if buf.len() < end {
            return Ok(None);
        }
        let payload = &buf[p..end];
        let frame = match frame_type {
            0x00 => Frame::Data(payload.to_vec()),
            0x01 => Frame::Headers(payload.to_vec()),
            0x03 => {
                let mut q = 0;
                let id = crate::courierust_h3::qpack::decode_integer(payload, 8, &mut q)?;
                if q != payload.len() {
                    return Err(Error::protocol("trailing bytes in CANCEL_PUSH"));
                }
                Frame::CancelPush(id)
            }
            0x04 => {
                let mut q = 0;
                let mut settings = Vec::new();
                while q < payload.len() {
                    if settings.len() >= MAX_SETTINGS_ENTRIES {
                        return Err(Error::overflow("HTTP/3 SETTINGS entry count exceeds limit"));
                    }
                    // RFC 9114 §7.2.4: SETTINGS entries are QUIC varints.
                    let (id, used) = crate::courierust_quic::varint::decode(&payload[q..])
                        .map_err(|e| Error::protocol(e.to_string()))?;
                    q = q
                        .checked_add(used)
                        .ok_or_else(|| Error::overflow("HTTP/3 SETTINGS id offset overflow"))?;
                    let (value, used) = crate::courierust_quic::varint::decode(&payload[q..])
                        .map_err(|e| Error::protocol(e.to_string()))?;
                    q = q
                        .checked_add(used)
                        .ok_or_else(|| Error::overflow("HTTP/3 SETTINGS value offset overflow"))?;
                    settings.push((id, value));
                }
                Frame::Settings(settings)
            }
            0x05 => {
                let mut q = 0;
                let push_id = crate::courierust_h3::qpack::decode_integer(payload, 8, &mut q)?;
                Frame::PushPromise {
                    push_id,
                    headers: payload[q..].to_vec(),
                }
            }
            0x07 => {
                let mut q = 0;
                let id = crate::courierust_h3::qpack::decode_integer(payload, 8, &mut q)?;
                if q != payload.len() {
                    return Err(Error::protocol("trailing bytes in GOAWAY"));
                }
                Frame::GoAway(id)
            }
            0x0d => {
                let mut q = 0;
                let id = crate::courierust_h3::qpack::decode_integer(payload, 8, &mut q)?;
                if q != payload.len() {
                    return Err(Error::protocol("trailing bytes in MAX_PUSH_ID"));
                }
                Frame::MaxPushId(id)
            }
            other => Frame::Unknown {
                frame_type: other,
                payload: payload.to_vec(),
            },
        };
        *pos = end;
        Ok(Some(frame))
    }
}

/// Encode the leading stream-type varint of a unidirectional stream.
pub fn encode_stream_type(stream_type: u64) -> Vec<u8> {
    crate::courierust_quic::varint::encode(stream_type)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(frame: Frame) {
        let wire = frame.to_bytes();
        let mut pos = 0;
        let decoded = Frame::decode(&wire, &mut pos)
            .unwrap()
            .expect("complete frame");
        assert_eq!(decoded, frame, "round trip for {frame:?}");
        assert_eq!(pos, wire.len());
    }

    #[test]
    fn frames_round_trip() {
        round_trip(Frame::Data(b"payload".to_vec()));
        round_trip(Frame::Headers(vec![0x40 | 8, 0x00]));
        round_trip(Frame::CancelPush(3));
        round_trip(Frame::Settings(vec![
            (SETTINGS_QPACK_MAX_TABLE_CAPACITY, 4096),
            (SETTINGS_MAX_FIELD_SECTION_SIZE, 16384),
        ]));
        round_trip(Frame::PushPromise {
            push_id: 7,
            headers: vec![0x40 | 8],
        });
        round_trip(Frame::GoAway(1000));
        round_trip(Frame::MaxPushId(0));
    }

    #[test]
    fn partial_frame_returns_none() {
        let wire = Frame::Data(vec![1, 2, 3]).to_bytes();
        // Truncate the payload.
        let mut pos = 0;
        assert!(Frame::decode(&wire[..wire.len() - 2], &mut pos)
            .unwrap()
            .is_none());
    }
}
