//! HTTP/2 frame codec (RFC 9113 §4, §6) plus the RFC 9218
//! PRIORITY_UPDATE frame.

use crate::courierust_bytes::{Bytes, BytesMut};
use crate::courierust_error::{Error, Result};
use crate::courierust_h2::error::ErrorCode;
use crate::courierust_h2::settings::Setting;
use alloc::vec::Vec;

/// Size of a frame header.
pub const FRAME_HEADER_LEN: usize = 9;

/// The 24-byte client connection preface.
pub const CLIENT_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Frame types.
pub mod kind {
    /// DATA
    pub const DATA: u8 = 0x0;
    /// HEADERS
    pub const HEADERS: u8 = 0x1;
    /// PRIORITY
    pub const PRIORITY: u8 = 0x2;
    /// RST_STREAM
    pub const RST_STREAM: u8 = 0x3;
    /// SETTINGS
    pub const SETTINGS: u8 = 0x4;
    /// PUSH_PROMISE
    pub const PUSH_PROMISE: u8 = 0x5;
    /// PING
    pub const PING: u8 = 0x6;
    /// GOAWAY
    pub const GOAWAY: u8 = 0x7;
    /// WINDOW_UPDATE
    pub const WINDOW_UPDATE: u8 = 0x8;
    /// CONTINUATION
    pub const CONTINUATION: u8 = 0x9;
    /// PRIORITY_UPDATE (RFC 9218 §7.1)
    pub const PRIORITY_UPDATE: u8 = 0x10;
}

/// Frame flags.
pub mod flag {
    /// END_STREAM (DATA, HEADERS)
    pub const END_STREAM: u8 = 0x1;
    /// ACK (SETTINGS, PING)
    pub const ACK: u8 = 0x1;
    /// END_HEADERS (HEADERS, PUSH_PROMISE, CONTINUATION)
    pub const END_HEADERS: u8 = 0x4;
    /// PADDED (DATA, HEADERS, PUSH_PROMISE)
    pub const PADDED: u8 = 0x8;
    /// PRIORITY (HEADERS)
    pub const PRIORITY: u8 = 0x20;
}

/// Decoded frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    /// Payload length.
    pub len: u32,
    /// Frame type.
    pub kind: u8,
    /// Flags.
    pub flags: u8,
    /// Stream identifier (31 bits).
    pub stream_id: u32,
}

/// An RFC 7540-style stream priority (deprecated by RFC 9218 but still
/// parsed for compatibility).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LegacyPriority {
    /// Parent stream id.
    pub dependency: u32,
    /// Exclusive flag.
    pub exclusive: bool,
    /// Weight 1..=256.
    pub weight: u8,
}

/// A decoded frame (payload interpreted).
#[derive(Debug, Clone, PartialEq)]
pub enum Frame {
    /// DATA (§6.1)
    Data {
        /// Stream id.
        stream_id: u32,
        /// Payload (padding stripped).
        data: Bytes,
        /// END_STREAM flag.
        end_stream: bool,
    },
    /// HEADERS (§6.2) — a single fragment; CONTINUATION is handled by
    /// the connection reassembler.
    Headers {
        /// Stream id.
        stream_id: u32,
        /// Fragment of the HPACK block.
        block: Bytes,
        /// END_STREAM flag.
        end_stream: bool,
        /// Whether this is the final fragment of the block.
        end_headers: bool,
        /// Optional RFC 7540 priority attached to the HEADERS.
        priority: Option<LegacyPriority>,
    },
    /// PRIORITY (§6.3)
    Priority {
        /// Stream id.
        stream_id: u32,
        /// Priority fields.
        priority: LegacyPriority,
    },
    /// RST_STREAM (§6.4)
    RstStream {
        /// Stream id.
        stream_id: u32,
        /// Error code.
        error_code: ErrorCode,
    },
    /// SETTINGS (§6.5)
    Settings {
        /// Whether this is an acknowledgement.
        ack: bool,
        /// Entries (empty for ACK).
        entries: Vec<Setting>,
    },
    /// PUSH_PROMISE (§6.6)
    PushPromise {
        /// Stream id.
        stream_id: u32,
        /// Promised stream id.
        promised_id: u32,
        /// HPACK fragment.
        block: Bytes,
        /// Whether this is the final fragment.
        end_headers: bool,
    },
    /// PING (§6.7)
    Ping {
        /// Whether this is an acknowledgement.
        ack: bool,
        /// 8-byte opaque data.
        data: [u8; 8],
    },
    /// GOAWAY (§6.8)
    GoAway {
        /// Last processed stream id.
        last_stream_id: u32,
        /// Error code.
        error_code: ErrorCode,
        /// Debug data.
        debug: Bytes,
    },
    /// WINDOW_UPDATE (§6.9)
    WindowUpdate {
        /// Stream id (0 = connection).
        stream_id: u32,
        /// Increment.
        increment: u32,
    },
    /// CONTINUATION (§6.10)
    Continuation {
        /// Stream id.
        stream_id: u32,
        /// Whether this is the final fragment.
        end_headers: bool,
        /// HPACK fragment.
        block: Bytes,
    },
    /// PRIORITY_UPDATE (RFC 9218 §7.1)
    PriorityUpdate {
        /// The stream being prioritized.
        prioritized_stream_id: u32,
        /// The priority field value (ASCII structured-field).
        priority_field: Bytes,
    },
    /// An unknown frame type; receivers ignore it (RFC 9113 §4.1).
    Unknown {
        /// Frame type.
        kind: u8,
        /// Flags.
        flags: u8,
        /// Stream id.
        stream_id: u32,
        /// Raw payload.
        payload: Bytes,
    },
}

impl Frame {
    /// Parse a frame from a header + payload. `max_frame_size` is the
    /// largest payload we accept.
    pub fn parse(header: FrameHeader, payload: &[u8], max_frame_size: u32) -> Result<Frame> {
        if header.len as usize != payload.len() {
            return Err(Error::protocol("frame length mismatch"));
        }
        if header.len > max_frame_size {
            return Err(Error::h2(
                ErrorCode::FrameSizeError.as_u32(),
                "frame exceeds max frame size",
            ));
        }
        let sid = header.stream_id;
        match header.kind {
            kind::DATA => {
                if sid == 0 {
                    return Err(Error::h2(
                        ErrorCode::ProtocolError.as_u32(),
                        "DATA on stream 0",
                    ));
                }
                let (data, pad) = strip_padding(payload, header.flags, flag::PADDED)?;
                let _ = pad;
                Ok(Frame::Data {
                    stream_id: sid,
                    data: Bytes::from(data),
                    end_stream: header.flags & flag::END_STREAM != 0,
                })
            }
            kind::HEADERS => {
                if sid == 0 {
                    return Err(Error::h2(
                        ErrorCode::ProtocolError.as_u32(),
                        "HEADERS on stream 0",
                    ));
                }
                let mut rest = payload;
                let pad_len = if header.flags & flag::PADDED != 0 {
                    let p = *rest.first().ok_or_else(|| {
                        Error::h2(ErrorCode::FrameSizeError.as_u32(), "padded HEADERS empty")
                    })? as usize;
                    rest = &rest[1..];
                    p
                } else {
                    0
                };
                let priority = if header.flags & flag::PRIORITY != 0 {
                    let raw = rest.get(..5).ok_or_else(|| {
                        Error::h2(
                            ErrorCode::FrameSizeError.as_u32(),
                            "HEADERS priority truncated",
                        )
                    })?;
                    let dep = u32::from_be_bytes([raw[0] & 0x7f, raw[1], raw[2], raw[3]]);
                    let weight = raw[4].wrapping_add(1);
                    rest = &rest[5..];
                    Some(LegacyPriority {
                        dependency: dep,
                        exclusive: raw[0] & 0x80 != 0,
                        weight,
                    })
                } else {
                    None
                };
                if rest.len() + pad_len > payload.len() {
                    return Err(Error::h2(
                        ErrorCode::FrameSizeError.as_u32(),
                        "HEADERS padding overrun",
                    ));
                }
                let block_len = rest.len().saturating_sub(pad_len);
                Ok(Frame::Headers {
                    stream_id: sid,
                    block: Bytes::from(&rest[..block_len]),
                    end_stream: header.flags & flag::END_STREAM != 0,
                    end_headers: header.flags & flag::END_HEADERS != 0,
                    priority,
                })
            }
            kind::PRIORITY => {
                if sid == 0 {
                    return Err(Error::h2(
                        ErrorCode::ProtocolError.as_u32(),
                        "PRIORITY on stream 0",
                    ));
                }
                if payload.len() != 5 {
                    return Err(Error::h2(
                        ErrorCode::FrameSizeError.as_u32(),
                        "PRIORITY length != 5",
                    ));
                }
                let dep =
                    u32::from_be_bytes([payload[0] & 0x7f, payload[1], payload[2], payload[3]]);
                Ok(Frame::Priority {
                    stream_id: sid,
                    priority: LegacyPriority {
                        dependency: dep,
                        exclusive: payload[0] & 0x80 != 0,
                        weight: payload[4].wrapping_add(1),
                    },
                })
            }
            kind::RST_STREAM => {
                if sid == 0 {
                    return Err(Error::h2(
                        ErrorCode::ProtocolError.as_u32(),
                        "RST_STREAM on stream 0",
                    ));
                }
                if payload.len() != 4 {
                    return Err(Error::h2(
                        ErrorCode::FrameSizeError.as_u32(),
                        "RST_STREAM length != 4",
                    ));
                }
                let code = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                Ok(Frame::RstStream {
                    stream_id: sid,
                    error_code: ErrorCode::from_u32(code).unwrap_or(ErrorCode::NoError),
                })
            }
            kind::SETTINGS => {
                if sid != 0 {
                    return Err(Error::h2(
                        ErrorCode::ProtocolError.as_u32(),
                        "SETTINGS on stream != 0",
                    ));
                }
                let ack = header.flags & flag::ACK != 0;
                if ack {
                    if !payload.is_empty() {
                        return Err(Error::h2(
                            ErrorCode::FrameSizeError.as_u32(),
                            "SETTINGS ACK with payload",
                        ));
                    }
                    return Ok(Frame::Settings {
                        ack: true,
                        entries: Vec::new(),
                    });
                }
                if !payload.len().is_multiple_of(6) {
                    return Err(Error::h2(
                        ErrorCode::FrameSizeError.as_u32(),
                        "SETTINGS length % 6 != 0",
                    ));
                }
                let (chunks, remainder) = payload.as_chunks::<6>();
                debug_assert!(remainder.is_empty());
                let mut entries = Vec::with_capacity(chunks.len());
                for c in chunks {
                    let id = u16::from_be_bytes([c[0], c[1]]);
                    let value = u32::from_be_bytes([c[2], c[3], c[4], c[5]]);
                    entries.push(Setting { id, value });
                }
                Ok(Frame::Settings {
                    ack: false,
                    entries,
                })
            }
            kind::PUSH_PROMISE => {
                if sid == 0 {
                    return Err(Error::h2(
                        ErrorCode::ProtocolError.as_u32(),
                        "PUSH_PROMISE on stream 0",
                    ));
                }
                let mut rest = payload;
                let pad_len = if header.flags & flag::PADDED != 0 {
                    let p = *rest.first().ok_or_else(|| {
                        Error::h2(
                            ErrorCode::FrameSizeError.as_u32(),
                            "padded PUSH_PROMISE empty",
                        )
                    })? as usize;
                    rest = &rest[1..];
                    p
                } else {
                    0
                };
                let promised = rest.get(..4).ok_or_else(|| {
                    Error::h2(ErrorCode::FrameSizeError.as_u32(), "PUSH_PROMISE truncated")
                })?;
                let promised_id =
                    u32::from_be_bytes([promised[0] & 0x7f, promised[1], promised[2], promised[3]]);
                rest = &rest[4..];
                if rest.len() + pad_len > payload.len() {
                    return Err(Error::h2(
                        ErrorCode::FrameSizeError.as_u32(),
                        "PUSH_PROMISE padding overrun",
                    ));
                }
                let block_len = rest.len().saturating_sub(pad_len);
                Ok(Frame::PushPromise {
                    stream_id: sid,
                    promised_id,
                    block: Bytes::from(&rest[..block_len]),
                    end_headers: header.flags & flag::END_HEADERS != 0,
                })
            }
            kind::PING => {
                if sid != 0 {
                    return Err(Error::h2(
                        ErrorCode::ProtocolError.as_u32(),
                        "PING on stream != 0",
                    ));
                }
                if payload.len() != 8 {
                    return Err(Error::h2(
                        ErrorCode::FrameSizeError.as_u32(),
                        "PING length != 8",
                    ));
                }
                let mut data = [0u8; 8];
                data.copy_from_slice(payload);
                Ok(Frame::Ping {
                    ack: header.flags & flag::ACK != 0,
                    data,
                })
            }
            kind::GOAWAY => {
                if sid != 0 {
                    return Err(Error::h2(
                        ErrorCode::ProtocolError.as_u32(),
                        "GOAWAY on stream != 0",
                    ));
                }
                if payload.len() < 8 {
                    return Err(Error::h2(
                        ErrorCode::FrameSizeError.as_u32(),
                        "GOAWAY too short",
                    ));
                }
                let last =
                    u32::from_be_bytes([payload[0] & 0x7f, payload[1], payload[2], payload[3]]);
                let code = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
                Ok(Frame::GoAway {
                    last_stream_id: last,
                    error_code: ErrorCode::from_u32(code).unwrap_or(ErrorCode::NoError),
                    debug: Bytes::from(&payload[8..]),
                })
            }
            kind::WINDOW_UPDATE => {
                if payload.len() != 4 {
                    return Err(Error::h2(
                        ErrorCode::FrameSizeError.as_u32(),
                        "WINDOW_UPDATE length != 4",
                    ));
                }
                let inc =
                    u32::from_be_bytes([payload[0] & 0x7f, payload[1], payload[2], payload[3]]);
                if inc == 0 {
                    return Err(Error::h2(
                        ErrorCode::ProtocolError.as_u32(),
                        "WINDOW_UPDATE increment 0",
                    ));
                }
                Ok(Frame::WindowUpdate {
                    stream_id: sid,
                    increment: inc,
                })
            }
            kind::CONTINUATION => {
                if sid == 0 {
                    return Err(Error::h2(
                        ErrorCode::ProtocolError.as_u32(),
                        "CONTINUATION on stream 0",
                    ));
                }
                Ok(Frame::Continuation {
                    stream_id: sid,
                    end_headers: header.flags & flag::END_HEADERS != 0,
                    block: Bytes::from(payload),
                })
            }
            kind::PRIORITY_UPDATE => {
                if sid != 0 {
                    return Err(Error::h2(
                        ErrorCode::ProtocolError.as_u32(),
                        "PRIORITY_UPDATE on stream != 0",
                    ));
                }
                if payload.len() < 4 {
                    return Err(Error::h2(
                        ErrorCode::FrameSizeError.as_u32(),
                        "PRIORITY_UPDATE too short",
                    ));
                }
                let prioritized =
                    u32::from_be_bytes([payload[0] & 0x7f, payload[1], payload[2], payload[3]]);
                if prioritized == 0 {
                    return Err(Error::h2(
                        ErrorCode::ProtocolError.as_u32(),
                        "PRIORITY_UPDATE stream 0",
                    ));
                }
                Ok(Frame::PriorityUpdate {
                    prioritized_stream_id: prioritized,
                    priority_field: Bytes::from(&payload[4..]),
                })
            }
            other => Ok(Frame::Unknown {
                kind: other,
                flags: header.flags,
                stream_id: sid,
                payload: Bytes::from(payload),
            }),
        }
    }

    /// Serialize a frame into `out`.
    pub fn encode(&self, out: &mut BytesMut) {
        match self {
            Frame::Data {
                stream_id,
                data,
                end_stream,
            } => {
                let mut f = 0u8;
                if *end_stream {
                    f |= flag::END_STREAM;
                }
                encode_header(data.len() as u32, kind::DATA, f, *stream_id, out);
                out.extend_from_slice(data);
            }
            Frame::Headers {
                stream_id,
                block,
                end_stream,
                end_headers,
                priority,
            } => {
                let mut f = 0u8;
                if *end_stream {
                    f |= flag::END_STREAM;
                }
                if *end_headers {
                    f |= flag::END_HEADERS;
                }
                let mut payload = BytesMut::with_capacity(block.len() + 5);
                if let Some(p) = priority {
                    f |= flag::PRIORITY;
                    let mut dep = p.dependency;
                    if p.exclusive {
                        dep |= 0x8000_0000;
                    }
                    payload.put_u32(dep);
                    payload.put_u8(p.weight.wrapping_sub(1));
                }
                payload.extend_from_slice(block);
                encode_header(payload.len() as u32, kind::HEADERS, f, *stream_id, out);
                out.extend_from_slice(payload.as_slice());
            }
            Frame::Priority {
                stream_id,
                priority,
            } => {
                let mut payload = BytesMut::with_capacity(5);
                let mut dep = priority.dependency;
                if priority.exclusive {
                    dep |= 0x8000_0000;
                }
                payload.put_u32(dep);
                payload.put_u8(priority.weight.wrapping_sub(1));
                encode_header(5, kind::PRIORITY, 0, *stream_id, out);
                out.extend_from_slice(payload.as_slice());
            }
            Frame::RstStream {
                stream_id,
                error_code,
            } => {
                let mut payload = BytesMut::with_capacity(4);
                payload.put_u32(error_code.as_u32());
                encode_header(4, kind::RST_STREAM, 0, *stream_id, out);
                out.extend_from_slice(payload.as_slice());
            }
            Frame::Settings { ack, entries } => {
                let flags = if *ack { flag::ACK } else { 0 };
                let mut payload = BytesMut::with_capacity(entries.len() * 6);
                for s in entries {
                    payload.put_u16(s.id);
                    payload.put_u32(s.value);
                }
                encode_header(payload.len() as u32, kind::SETTINGS, flags, 0, out);
                out.extend_from_slice(payload.as_slice());
            }
            Frame::PushPromise {
                stream_id,
                promised_id,
                block,
                end_headers,
            } => {
                let flags = if *end_headers { flag::END_HEADERS } else { 0 };
                let mut payload = BytesMut::with_capacity(block.len() + 4);
                payload.put_u32(*promised_id & 0x7fff_ffff);
                payload.extend_from_slice(block);
                encode_header(
                    payload.len() as u32,
                    kind::PUSH_PROMISE,
                    flags,
                    *stream_id,
                    out,
                );
                out.extend_from_slice(payload.as_slice());
            }
            Frame::Ping { ack, data } => {
                let flags = if *ack { flag::ACK } else { 0 };
                encode_header(8, kind::PING, flags, 0, out);
                out.extend_from_slice(data);
            }
            Frame::GoAway {
                last_stream_id,
                error_code,
                debug,
            } => {
                let mut payload = BytesMut::with_capacity(debug.len() + 8);
                payload.put_u32(*last_stream_id & 0x7fff_ffff);
                payload.put_u32(error_code.as_u32());
                payload.extend_from_slice(debug);
                encode_header(payload.len() as u32, kind::GOAWAY, 0, 0, out);
                out.extend_from_slice(payload.as_slice());
            }
            Frame::WindowUpdate {
                stream_id,
                increment,
            } => {
                let mut payload = BytesMut::with_capacity(4);
                payload.put_u32(*increment & 0x7fff_ffff);
                encode_header(4, kind::WINDOW_UPDATE, 0, *stream_id, out);
                out.extend_from_slice(payload.as_slice());
            }
            Frame::Continuation {
                stream_id,
                end_headers,
                block,
            } => {
                let flags = if *end_headers { flag::END_HEADERS } else { 0 };
                encode_header(
                    block.len() as u32,
                    kind::CONTINUATION,
                    flags,
                    *stream_id,
                    out,
                );
                out.extend_from_slice(block);
            }
            Frame::PriorityUpdate {
                prioritized_stream_id,
                priority_field,
            } => {
                let mut payload = BytesMut::with_capacity(priority_field.len() + 4);
                payload.put_u32(*prioritized_stream_id & 0x7fff_ffff);
                payload.extend_from_slice(priority_field);
                encode_header(payload.len() as u32, kind::PRIORITY_UPDATE, 0, 0, out);
                out.extend_from_slice(payload.as_slice());
            }
            Frame::Unknown {
                kind,
                flags,
                stream_id,
                payload,
            } => {
                encode_header(payload.len() as u32, *kind, *flags, *stream_id, out);
                out.extend_from_slice(payload);
            }
        }
    }

    /// The frame's own stream id (0 for connection-level frames).
    pub fn stream_id(&self) -> u32 {
        match self {
            Frame::Data { stream_id, .. }
            | Frame::Headers { stream_id, .. }
            | Frame::Priority { stream_id, .. }
            | Frame::RstStream { stream_id, .. }
            | Frame::PushPromise { stream_id, .. }
            | Frame::Continuation { stream_id, .. }
            | Frame::WindowUpdate { stream_id, .. } => *stream_id,
            _ => 0,
        }
    }
}

/// Strip the Pad Length field and trailing padding from a payload.
fn strip_padding(payload: &[u8], flags: u8, padded_flag: u8) -> Result<(&[u8], usize)> {
    if flags & padded_flag == 0 {
        return Ok((payload, 0));
    }
    let pad = *payload
        .first()
        .ok_or_else(|| Error::h2(ErrorCode::FrameSizeError.as_u32(), "padded frame empty"))?
        as usize;
    if pad >= payload.len() {
        return Err(Error::h2(
            ErrorCode::FrameSizeError.as_u32(),
            "padding overrun",
        ));
    }
    Ok((&payload[1..payload.len() - pad], pad))
}

/// Encode a 9-byte frame header.
pub fn encode_header(len: u32, kind: u8, flags: u8, stream_id: u32, out: &mut BytesMut) {
    out.put_u24(len);
    out.put_u8(kind);
    out.put_u8(flags);
    out.put_u32(stream_id & 0x7fff_ffff);
}

/// Decode a 9-byte frame header.
pub fn decode_header(b: &[u8; 9]) -> FrameHeader {
    FrameHeader {
        len: ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | (b[2] as u32),
        kind: b[3],
        flags: b[4],
        stream_id: u32::from_be_bytes([b[5] & 0x7f, b[6], b[7], b[8]]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::courierust_h2::settings::{
        SETTINGS_HEADER_TABLE_SIZE, SETTINGS_INITIAL_WINDOW_SIZE,
    };

    fn roundtrip(f: &Frame) {
        let mut buf = BytesMut::new();
        f.encode(&mut buf);
        let header = decode_header(&buf.as_slice()[..9].try_into().unwrap());
        let parsed = Frame::parse(header, &buf.as_slice()[9..], 1 << 24).unwrap();
        assert_eq!(&parsed, f);
    }

    #[test]
    fn roundtrip_frames() {
        roundtrip(&Frame::Data {
            stream_id: 1,
            data: Bytes::from_static(b"hello"),
            end_stream: true,
        });
        roundtrip(&Frame::Headers {
            stream_id: 3,
            block: Bytes::from_static(&[0x82, 0x86, 0x84]),
            end_stream: false,
            end_headers: true,
            priority: None,
        });
        roundtrip(&Frame::RstStream {
            stream_id: 5,
            error_code: ErrorCode::Cancel,
        });
        roundtrip(&Frame::Settings {
            ack: false,
            entries: vec![
                Setting {
                    id: SETTINGS_HEADER_TABLE_SIZE,
                    value: 4096,
                },
                Setting {
                    id: SETTINGS_INITIAL_WINDOW_SIZE,
                    value: 65535,
                },
            ],
        });
        roundtrip(&Frame::Settings {
            ack: true,
            entries: vec![],
        });
        roundtrip(&Frame::Ping {
            ack: false,
            data: [1, 2, 3, 4, 5, 6, 7, 8],
        });
        roundtrip(&Frame::GoAway {
            last_stream_id: 100,
            error_code: ErrorCode::NoError,
            debug: Bytes::from_static(b"bye"),
        });
        roundtrip(&Frame::WindowUpdate {
            stream_id: 0,
            increment: 65535,
        });
        roundtrip(&Frame::PriorityUpdate {
            prioritized_stream_id: 7,
            priority_field: Bytes::from_static(b"u=0, i"),
        });
    }

    #[test]
    fn parses_client_preface_frames() {
        // The SETTINGS frame Chrome sends is exactly 6 bytes of entries.
        let mut buf = BytesMut::new();
        Frame::Settings {
            ack: false,
            entries: vec![
                Setting {
                    id: SETTINGS_HEADER_TABLE_SIZE,
                    value: 65536,
                },
                Setting {
                    id: SETTINGS_INITIAL_WINDOW_SIZE,
                    value: 6291456,
                },
            ],
        }
        .encode(&mut buf);
        let header = decode_header(&buf.as_slice()[..9].try_into().unwrap());
        assert_eq!(header.kind, kind::SETTINGS);
        assert_eq!(header.len, 12);
    }

    #[test]
    fn rejects_window_update_zero() {
        let mut buf = BytesMut::new();
        buf.put_u24(4);
        buf.put_u8(kind::WINDOW_UPDATE);
        buf.put_u8(0);
        buf.put_u32(1);
        buf.put_u32(0);
        let header = decode_header(&buf.as_slice()[..9].try_into().unwrap());
        assert!(Frame::parse(header, &buf.as_slice()[9..], 1 << 24).is_err());
    }
}
