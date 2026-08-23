//! A self-contained Protocol Buffers wire-format codec (proto3 binary
//! format) implemented from the public
//! [protobuf encoding specification](<https://protobuf.dev/programming-guides/encoding/>)
//! with no third-party crates.
//!
//! Supported scalars: varint (`int32/int64/uint32/uint64/sint32/sint64/
//! bool`), fixed (`fixed32/fixed64/float/double`), length-delimited
//! (`string/bytes`), plus `repeated` (packed for numerics) and
//! message-typed fields.

use crate::courierust_error::{Error, Result};
use alloc::vec::Vec;

/// Protobuf wire types
/// (<https://protobuf.dev/programming-guides/encoding/#structure>).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireType {
    /// 0 — varint.
    Varint,
    /// 1 — 64-bit.
    Fixed64,
    /// 2 — length-delimited.
    LengthDelimited,
    /// 5 — 32-bit.
    Fixed32,
}

impl WireType {
    /// The 3-bit wire type value.
    pub fn code(self) -> u8 {
        match self {
            WireType::Varint => 0,
            WireType::Fixed64 => 1,
            WireType::LengthDelimited => 2,
            WireType::Fixed32 => 5,
        }
    }

    /// Decode a 3-bit wire type value; invalid values (3, 4, 6, 7) are
    /// reserved and rejected.
    pub fn from_code(code: u8) -> Option<WireType> {
        match code {
            0 => Some(WireType::Varint),
            1 => Some(WireType::Fixed64),
            2 => Some(WireType::LengthDelimited),
            5 => Some(WireType::Fixed32),
            _ => None,
        }
    }
}

/// Encode a base-128 varint (protobuf unsigned integer encoding).
pub fn write_varint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            out.push(byte | 0x80);
        } else {
            out.push(byte);
            break;
        }
    }
}

/// Read a base-128 varint, rejecting over-long encodings and overflow.
pub fn read_varint(buf: &mut &[u8]) -> Result<u64> {
    let mut value: u64 = 0;
    let mut shift = 0u32;
    loop {
        let byte = *buf
            .first()
            .ok_or_else(|| Error::protocol("truncated protobuf varint"))?;
        *buf = &buf[1..];
        if shift >= 64 {
            return Err(Error::protocol("protobuf varint overflow"));
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift >= 64 && byte & 0x80 != 0 {
            return Err(Error::protocol("protobuf varint too long"));
        }
    }
    Ok(value)
}

/// Encode a `field_number` + `wire_type` tag.
pub fn write_tag(out: &mut Vec<u8>, number: u32, wire: WireType) {
    write_varint(out, (u64::from(number) << 3) | u64::from(wire.code()));
}

/// Read and decode a tag; returns `(field_number, wire_type)`.
pub fn read_tag(buf: &mut &[u8]) -> Result<(u32, WireType)> {
    let tag = read_varint(buf)?;
    let number = (tag >> 3) as u32;
    let wire = WireType::from_code((tag & 0x7) as u8)
        .ok_or_else(|| Error::protocol("invalid protobuf wire type"))?;
    if number == 0 {
        return Err(Error::protocol("protobuf field number 0 is reserved"));
    }
    Ok((number, wire))
}

/// ZigZag encoding for `sint32`/`sint64` (signed varints).
pub fn zigzag_encode(value: i64) -> u64 {
    ((value << 1) ^ (value >> 63)) as u64
}

/// ZigZag decoding.
pub fn zigzag_decode(value: u64) -> i64 {
    ((value >> 1) as i64) ^ -((value & 1) as i64)
}

/// A bounded reader over the remaining payload of a length-delimited
/// field. Prevents a malicious length from reading past the enclosing
/// message and enforces an overall nesting budget.
pub struct SliceReader<'a> {
    buf: &'a [u8],
    /// Nesting depth budget (100, matching common parsers) to bound
    /// hostile deeply-nested messages.
    depth: u32,
}

const MAX_DEPTH: u32 = 100;

impl<'a> SliceReader<'a> {
    /// Create a reader over a message body.
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, depth: 0 }
    }

    /// Take `n` bytes, rejecting overruns.
    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if n > self.buf.len() {
            return Err(Error::protocol("protobuf field overruns message"));
        }
        let (head, tail) = self.buf.split_at(n);
        self.buf = tail;
        Ok(head)
    }

    /// The number of unread bytes.
    pub fn remaining(&self) -> usize {
        self.buf.len()
    }

    /// Read a varint from the stream.
    pub fn read_varint(&mut self) -> Result<u64> {
        read_varint(&mut self.buf)
    }

    /// Read a little-endian 64-bit fixed value.
    pub fn read_fixed64(&mut self) -> Result<u64> {
        let b = self.take(8)?;
        Ok(u64::from_le_bytes(b.try_into().unwrap()))
    }

    /// Read a little-endian 32-bit fixed value.
    pub fn read_fixed32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes(b.try_into().unwrap()))
    }

    /// Enter a length-delimited sub-message, applying the nesting budget.
    pub fn sub(&mut self, len: usize) -> Result<SliceReader<'a>> {
        if self.depth >= MAX_DEPTH {
            return Err(Error::protocol("protobuf message nesting too deep"));
        }
        let sub = self.take(len)?;
        Ok(SliceReader {
            buf: sub,
            depth: self.depth + 1,
        })
    }
}

/// A trait implemented by every generated protobuf message. `encode` and
/// `decode` cover the message *body* (fields only, no framing).
pub trait ProtoMessage: Sized {
    /// Append this message's fields to `out`.
    fn encode_message_body(&self, out: &mut Vec<u8>);
    /// Decode the message body from a length-delimited byte slice.
    fn decode_message_body(buf: &[u8]) -> Result<Self>;
}

/// Decode a length-delimited field whose content is itself a message.
pub fn decode_sub_message<M: ProtoMessage>(sub: &[u8]) -> Result<M> {
    M::decode_message_body(sub)
}

// ---------------------------------------------------------------------
// Scalar encode/decode helpers (used by generated code)
// ---------------------------------------------------------------------

/// Encode a varint-typed scalar field (`number` + varint value).
pub fn encode_varint_field(out: &mut Vec<u8>, number: u32, value: u64) {
    write_tag(out, number, WireType::Varint);
    write_varint(out, value);
}

/// Apply a decoded varint value (helper used by generated decoders).
pub fn decode_varint_field<F: FnOnce(u64) -> Result<()>>(value: u64, apply: F) -> Result<()> {
    apply(value)
}

/// Encode a length-delimited field whose payload is `value`.
pub fn encode_bytes_field(out: &mut Vec<u8>, number: u32, value: &[u8]) {
    write_tag(out, number, WireType::LengthDelimited);
    write_varint(out, value.len() as u64);
    out.extend_from_slice(value);
}

/// Encode a `string` field (UTF-8 length-delimited payload).
pub fn encode_string_field(out: &mut Vec<u8>, number: u32, value: &str) {
    encode_bytes_field(out, number, value.as_bytes());
}

/// Encode a packed repeated field from an already-built element payload.
pub fn encode_packed_payload(out: &mut Vec<u8>, number: u32, payload: &[u8]) {
    if payload.is_empty() {
        return;
    }
    write_tag(out, number, WireType::LengthDelimited);
    write_varint(out, payload.len() as u64);
    out.extend_from_slice(payload);
}

/// Append one varint element to a packed payload.
pub fn push_packed_varint(payload: &mut Vec<u8>, value: u64) {
    write_varint(payload, value);
}

/// Append one fixed64 element to a packed payload.
pub fn push_packed_fixed64(payload: &mut Vec<u8>, value: u64) {
    payload.extend_from_slice(&value.to_le_bytes());
}

/// Append one fixed32 element to a packed payload.
pub fn push_packed_fixed32(payload: &mut Vec<u8>, value: u32) {
    payload.extend_from_slice(&value.to_le_bytes());
}

// Per-scalar packed element encoders (used by the build-time generator).
macro_rules! packed_encoder {
    ($name:ident, $ty:ty, $body:expr) => {
        /// Append one element to a packed repeated payload.
        pub fn $name(payload: &mut Vec<u8>, value: $ty) {
            $body(payload, value);
        }
    };
}

packed_encoder!(push_packed_bool, bool, |p, v: bool| {
    push_packed_varint(p, u64::from(v))
});
packed_encoder!(push_packed_i32, i32, |p, v: i32| {
    push_packed_varint(p, v as i64 as u64)
});
packed_encoder!(push_packed_i64, i64, |p, v: i64| {
    push_packed_varint(p, v as u64)
});
packed_encoder!(push_packed_u32, u32, |p, v: u32| {
    push_packed_varint(p, u64::from(v))
});
packed_encoder!(push_packed_u64, u64, push_packed_varint);
packed_encoder!(push_packed_s32, i32, |p, v: i32| {
    push_packed_varint(p, zigzag_encode(i64::from(v)))
});
packed_encoder!(push_packed_s64, i64, |p, v: i64| {
    push_packed_varint(p, zigzag_encode(v))
});
packed_encoder!(push_packed_float, f32, |p, v: f32| {
    push_packed_fixed32(p, v.to_bits())
});
packed_encoder!(push_packed_double, f64, |p, v: f64| {
    push_packed_fixed64(p, v.to_bits())
});

/// Decode a packed repeated field's payload (varint elements).
pub fn decode_packed_varints(payload: &[u8]) -> Result<Vec<u64>> {
    let mut buf = payload;
    let mut out = Vec::new();
    while !buf.is_empty() {
        out.push(read_varint(&mut buf)?);
    }
    Ok(out)
}

/// Decode a packed repeated field's payload (fixed64 elements).
/// Decode a packed repeated field's payload (fixed64 elements). The
/// caller must have validated that `payload.len()` is a multiple of 8;
/// the chunk conversion below is therefore infallible.
pub fn decode_packed_fixed64s(payload: &[u8]) -> Result<Vec<u64>> {
    if !payload.len().is_multiple_of(8) {
        return Err(Error::protocol(
            "protobuf packed fixed64 length not a multiple of 8",
        ));
    }
    Ok(payload
        .as_chunks::<8>()
        .0
        .iter()
        .map(|c| u64::from_le_bytes(*c))
        .collect())
}

/// Decode a packed repeated field's payload (fixed32 elements). The
/// caller must have validated that `payload.len()` is a multiple of 4;
/// the chunk conversion below is therefore infallible.
pub fn decode_packed_fixed32s(payload: &[u8]) -> Result<Vec<u32>> {
    if !payload.len().is_multiple_of(4) {
        return Err(Error::protocol(
            "protobuf packed fixed32 length not a multiple of 4",
        ));
    }
    Ok(payload
        .as_chunks::<4>()
        .0
        .iter()
        .map(|c| u32::from_le_bytes(*c))
        .collect())
}

// Per-scalar packed element decoders and single-value converters (used
// by the build-time generator). `decode_packed_*` read a packed payload;
// `conv_*` convert a single decoded varint/fixed value.

macro_rules! packed_decoder {
    ($name:ident, $out:ty, $conv:path) => {
        /// Decode a packed repeated payload into its element type.
        pub fn $name(payload: &[u8]) -> Result<Vec<$out>> {
            Ok(decode_packed_varints(payload)?
                .into_iter()
                .map($conv)
                .collect())
        }
    };
}

packed_decoder!(decode_packed_bool, bool, varint_to_bool);
packed_decoder!(decode_packed_i32, i32, varint_to_i32);
packed_decoder!(decode_packed_i64, i64, varint_to_i64);
packed_decoder!(decode_packed_u32, u32, varint_to_u32);
packed_decoder!(decode_packed_s32, i32, zigzag_to_i32);
packed_decoder!(decode_packed_s64, i64, zigzag_to_i64);

/// Decode a packed `fixed32`/`float` payload.
pub fn decode_packed_float(payload: &[u8]) -> Result<Vec<f32>> {
    Ok(decode_packed_fixed32s(payload)?
        .into_iter()
        .map(|v| fixed32_to_f32(u64::from(v)))
        .collect())
}

/// Decode a packed `fixed64`/`double` payload.
pub fn decode_packed_double(payload: &[u8]) -> Result<Vec<f64>> {
    Ok(decode_packed_fixed64s(payload)?
        .into_iter()
        .map(fixed64_to_f64)
        .collect())
}

macro_rules! conv {
    ($name:ident, $ty:ty, $body:expr) => {
        /// Convert a single decoded scalar value to its Rust type.
        pub fn $name(value: u64) -> $ty {
            $body(value)
        }
    };
}

conv!(conv_bool, bool, varint_to_bool);
conv!(conv_i32, i32, varint_to_i32);
conv!(conv_i64, i64, varint_to_i64);
conv!(conv_u32, u32, varint_to_u32);
conv!(conv_u64, u64, |v| v);
conv!(conv_s32, i32, zigzag_to_i32);
conv!(conv_s64, i64, zigzag_to_i64);
conv!(conv_fixed32, u32, fixed32_to_u32);
conv!(conv_fixed64, u64, fixed64_to_u64);
conv!(conv_float, f32, fixed32_to_f32);
conv!(conv_double, f64, fixed64_to_f64);

/// A generic writer for the message macro: provides the per-field
/// encode helpers by type name.
pub struct Encoder;

/// Generated-code plumbing; the [`Encoder`] methods are documented by
/// their scalar type (they mirror the protobuf wire format).
#[allow(missing_docs)]
impl Encoder {
    pub fn string(out: &mut Vec<u8>, number: u32, value: &str) {
        encode_string_field(out, number, value);
    }
    pub fn bytes(out: &mut Vec<u8>, number: u32, value: &[u8]) {
        encode_bytes_field(out, number, value);
    }
    pub fn bool(out: &mut Vec<u8>, number: u32, value: bool) {
        encode_varint_field(out, number, u64::from(value));
    }
    pub fn int32(out: &mut Vec<u8>, number: u32, value: i32) {
        encode_varint_field(out, number, value as i64 as u64);
    }
    pub fn int64(out: &mut Vec<u8>, number: u32, value: i64) {
        encode_varint_field(out, number, value as u64);
    }
    pub fn uint32(out: &mut Vec<u8>, number: u32, value: u32) {
        encode_varint_field(out, number, u64::from(value));
    }
    pub fn uint64(out: &mut Vec<u8>, number: u32, value: u64) {
        encode_varint_field(out, number, value);
    }
    pub fn sint32(out: &mut Vec<u8>, number: u32, value: i32) {
        encode_varint_field(out, number, zigzag_encode(i64::from(value)));
    }
    pub fn sint64(out: &mut Vec<u8>, number: u32, value: i64) {
        encode_varint_field(out, number, zigzag_encode(value));
    }
    pub fn fixed32(out: &mut Vec<u8>, number: u32, value: u32) {
        write_tag(out, number, WireType::Fixed32);
        out.extend_from_slice(&value.to_le_bytes());
    }
    pub fn fixed64(out: &mut Vec<u8>, number: u32, value: u64) {
        write_tag(out, number, WireType::Fixed64);
        out.extend_from_slice(&value.to_le_bytes());
    }
    pub fn float(out: &mut Vec<u8>, number: u32, value: f32) {
        Self::fixed32(out, number, value.to_bits());
    }
    pub fn double(out: &mut Vec<u8>, number: u32, value: f64) {
        Self::fixed64(out, number, value.to_bits());
    }
    /// A message-typed field (proto3: present implies non-default; a
    /// None/Default value is omitted).
    pub fn message<M: ProtoMessage>(out: &mut Vec<u8>, number: u32, value: &M) {
        let mut body = Vec::new();
        value.encode_message_body(&mut body);
        encode_bytes_field(out, number, &body);
    }
}

/// A generic decoder: reads one field from `buf` and applies it.
pub struct Decoder;

/// Generated-code plumbing; [`Decoder::field`] is the single entry point
/// the message macro's decode path uses.
#[allow(missing_docs)]
impl Decoder {
    /// `apply(number, wire, value, payload)` — `value` is the raw varint
    /// or fixed value for scalar fields; `payload` is the byte slice for
    /// length-delimited fields.
    pub fn field(
        buf: &mut SliceReader<'_>,
        apply: impl FnOnce(u32, WireType, u64, &[u8]) -> Result<()>,
    ) -> Result<()> {
        let (number, wire) = read_tag(&mut buf.buf)?;
        match wire {
            WireType::Varint => {
                let value = buf.read_varint()?;
                apply(number, wire, value, &[])
            }
            WireType::Fixed64 => {
                let value = buf.read_fixed64()?;
                apply(number, wire, value, &[])
            }
            WireType::Fixed32 => {
                let value = u64::from(buf.read_fixed32()?);
                apply(number, wire, value, &[])
            }
            WireType::LengthDelimited => {
                let len = buf.read_varint()?;
                let len = usize::try_from(len)
                    .map_err(|_| Error::protocol("protobuf length overflow"))?;
                let payload = buf.take(len)?;
                apply(number, wire, 0, payload)
            }
        }
    }
}

/// Convert a decoded varint to an `i32` (two's complement).
pub fn varint_to_i32(value: u64) -> i32 {
    value as i64 as i32
}

/// Convert a decoded varint to an `i64`.
pub fn varint_to_i64(value: u64) -> i64 {
    value as i64
}

/// Convert a decoded varint to a `u32`.
pub fn varint_to_u32(value: u64) -> u32 {
    value as u32
}

/// Convert a decoded varint to a `bool`.
pub fn varint_to_bool(value: u64) -> bool {
    value != 0
}

/// Convert a decoded varint (zigzag) to an `i32`.
pub fn zigzag_to_i32(value: u64) -> i32 {
    zigzag_decode(value) as i32
}

/// Convert a decoded varint (zigzag) to an `i64`.
pub fn zigzag_to_i64(value: u64) -> i64 {
    zigzag_decode(value)
}

/// Convert a decoded fixed32 to a `u32` / `f32`.
pub fn fixed32_to_f32(value: u64) -> f32 {
    f32::from_bits(value as u32)
}

/// Convert a decoded fixed64 to a `f64`.
pub fn fixed64_to_f64(value: u64) -> f64 {
    f64::from_bits(value)
}

/// Convert a decoded fixed64 to a `u64`.
pub fn fixed64_to_u64(value: u64) -> u64 {
    value
}

/// Convert a decoded fixed32 to a `u32`.
pub fn fixed32_to_u32(value: u64) -> u32 {
    value as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_round_trip_all_widths() {
        for value in [
            0u64,
            1,
            127,
            128,
            300,
            16383,
            16384,
            u32::MAX as u64,
            u64::MAX,
        ] {
            let mut out = Vec::new();
            write_varint(&mut out, value);
            let mut buf = &out[..];
            assert_eq!(read_varint(&mut buf).unwrap(), value);
            assert!(buf.is_empty());
        }
    }

    #[test]
    fn tag_round_trip() {
        let mut out = Vec::new();
        write_tag(&mut out, 15, WireType::LengthDelimited);
        let mut buf = &out[..];
        assert_eq!(read_tag(&mut buf).unwrap(), (15, WireType::LengthDelimited));
    }

    #[test]
    fn overlong_varint_rejected() {
        // A varint with 11 continuation bytes overflows u64.
        let data = [
            0x80u8, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01,
        ];
        let mut buf = &data[..];
        assert!(read_varint(&mut buf).is_err());
    }

    #[test]
    fn zigzag_round_trip() {
        for value in [0i64, -1, 1, -2, 2, i32::MAX as i64, i32::MIN as i64] {
            assert_eq!(zigzag_decode(zigzag_encode(value)), value);
        }
    }

    #[test]
    fn slice_reader_rejects_overrun() {
        let data = [1u8, 2, 3];
        let mut reader = SliceReader::new(&data);
        assert!(reader.take(4).is_err());
        assert_eq!(reader.take(3).unwrap(), &data);
    }

    #[test]
    fn decode_unknown_and_known_fields() {
        // Wire: {1: "abc" (len-delim), 2: 7 (varint)}
        let mut encoded = Vec::new();
        encode_string_field(&mut encoded, 1, "abc");
        encode_varint_field(&mut encoded, 2, 7);
        let mut reader = SliceReader::new(&encoded);
        let mut s = alloc::string::String::new();
        let mut n = 0u64;
        while reader.remaining() > 0 {
            let applied = Decoder::field(&mut reader, |number, wire, value, payload| {
                match (number, wire) {
                    (1, WireType::LengthDelimited) => {
                        s = alloc::string::String::from_utf8(payload.to_vec())
                            .map_err(|_| Error::protocol("invalid utf8"))?;
                    }
                    (2, WireType::Varint) => n = value,
                    _ => {}
                }
                Ok(())
            });
            applied.expect("field decode");
        }
        assert_eq!(s, "abc");
        assert_eq!(n, 7);
    }
}
