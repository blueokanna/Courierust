//! HPACK (RFC 7541): header block encoder and decoder.
//!
//! The decoder is the correctness-critical half — it is validated
//! against the RFC 7541 Appendix C byte examples. The encoder is
//! free-form (RFC grants encoders latitude) but follows the canonical
//! strategy: full-match indexed, then literal-with-indexed-name plus
//! incremental indexing for reusable values, never-indexed for
//! sensitive fields, Huffman when it shortens the wire form.

pub mod huffman;
pub mod huffman_table;
pub mod table;

use crate::bytes::{Bytes, BytesMut};
use crate::error::{Error, Result};
use crate::http::header::{HeaderName, HeaderValue};
use crate::hpack::huffman::{encode as huffman_encode, HuffmanDecoder};
use crate::hpack::table::Table;
use alloc::vec::Vec;

/// One decoded/encoded header field with its sensitivity marker.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderField {
    /// Field name (lowercase; pseudo-headers start with `:`).
    pub name: HeaderName,
    /// Field value.
    pub value: HeaderValue,
    /// True when the peer demanded (or we chose) that this field never be
    /// added to the dynamic table and must be re-encoded as never-indexed.
    pub never_indexed: bool,
}

impl HeaderField {
    /// Build an ordinary (indexable) field.
    pub fn new(name: HeaderName, value: HeaderValue) -> Self {
        Self {
            name,
            value,
            never_indexed: false,
        }
    }

    /// Build a never-indexed field (sensitive value).
    pub fn new_never_indexed(name: HeaderName, value: HeaderValue) -> Self {
        Self {
            name,
            value,
            never_indexed: true,
        }
    }
}

/// A header block: an ordered list of fields.
pub type HeaderList = Vec<HeaderField>;

/// Names that are conventionally never compressed (RFC 7541 §7.1.3).
const SENSITIVE_NAMES: [&str; 4] = ["authorization", "cookie", "proxy-authorization", "set-cookie"];

/// Read an RFC 7541 §5.1 integer with an `n`-bit prefix whose value bits
/// are in `prefix`. `pos` is advanced past continuation octets.
fn read_int(input: &[u8], pos: &mut usize, n: u8, prefix: u8) -> Result<usize> {
    let max_prefix = (1u16 << n) - 1;
    let mut val = prefix as usize;
    if (prefix as u16) < max_prefix {
        return Ok(val);
    }
    let mut shift = 0usize;
    loop {
        if *pos >= input.len() {
            return Err(Error::protocol("HPACK: truncated integer"));
        }
        let b = input[*pos];
        *pos += 1;
        val += ((b & 0x7f) as usize) << shift;
        if b & 0x80 == 0 {
            return Ok(val);
        }
        shift += 7;
        if shift > 63 {
            return Err(Error::overflow("HPACK: integer too large"));
        }
    }
}

/// Read an RFC 7541 §5.2 string literal (Huffman bit + 7-bit length).
fn read_string(input: &[u8], pos: &mut usize, max_len: usize, huff: &HuffmanDecoder) -> Result<Bytes> {
    if *pos >= input.len() {
        return Err(Error::protocol("HPACK: truncated string"));
    }
    let b = input[*pos];
    *pos += 1;
    let huffman = b & 0x80 != 0;
    let len = read_int(input, pos, 7, b & 0x7f)?;
    if len > max_len {
        return Err(Error::overflow("HPACK: string exceeds limit"));
    }
    if *pos + len > input.len() {
        return Err(Error::protocol("HPACK: truncated string data"));
    }
    let raw = &input[*pos..*pos + len];
    *pos += len;
    if huffman {
        let mut out = Vec::with_capacity(len);
        huff.decode(raw, &mut out).map_err(|e| {
            Error::protocol(format!("HPACK: Huffman decode error: {e:?}"))
        })?;
        Ok(Bytes::from(out))
    } else {
        Ok(Bytes::from(raw))
    }
}

/// HPACK decoder (RFC 7541 §3). One instance per direction per
/// connection.
pub struct Decoder {
    table: Table,
    huff: HuffmanDecoder,
    /// The maximum dynamic-table size WE advertised via
    /// SETTINGS_HEADER_TABLE_SIZE; the peer's size updates must not
    /// exceed it.
    max_table_size: usize,
    /// Cap on the summed size of one decoded header list.
    max_header_list_size: usize,
    /// Cap on a single string literal.
    max_string_size: usize,
}

impl Decoder {
    /// New decoder. `max_table_size` is what we advertised to the peer;
    /// `max_header_list_size` is our SETTINGS_MAX_HEADER_LIST_SIZE.
    pub fn new(max_table_size: usize, max_header_list_size: usize) -> Self {
        Self {
            table: Table::default(),
            huff: HuffmanDecoder::new(),
            max_table_size,
            max_header_list_size,
            max_string_size: core::cmp::max(max_header_list_size * 4, 1 << 20),
        }
    }

    /// Current dynamic-table occupancy (bytes).
    #[inline]
    pub fn table_size(&self) -> usize {
        self.table.size()
    }

    /// Decode a complete header block.
    pub fn decode(&mut self, input: &[u8]) -> Result<HeaderList> {
        let mut out = HeaderList::new();
        let mut total = 0usize;
        let mut pos = 0usize;
        let mut saw_rep = false;
        while pos < input.len() {
            let b = input[pos];
            if b & 0x80 != 0 {
                // Indexed header field (§6.1)
                let idx = read_int(input, &mut pos, 7, b & 0x7f)?;
                if idx == 0 {
                    return Err(Error::protocol("HPACK: indexed with index 0"));
                }
                let (n, v) = self
                    .table
                    .get(idx)
                    .ok_or_else(|| Error::protocol("HPACK: index out of range"))?;
                let name = HeaderName::from_hpack_bytes(n)?;
                let value = HeaderValue::from_bytes(v)?;
                total = checked_add(total, n.len() + v.len())?;
                if total > self.max_header_list_size {
                    return Err(Error::overflow("HPACK: header list too large"));
                }
                out.push(HeaderField::new(name, value));
                saw_rep = true;
            } else if b & 0x40 != 0 {
                // Literal with incremental indexing (§6.2.1)
                let name_idx = read_int(input, &mut pos, 6, b & 0x3f)?;
                let (name_bytes, name_len) = if name_idx == 0 {
                    let s = read_string(input, &mut pos, self.max_string_size, &self.huff)?;
                    let l = s.len();
                    (s, l)
                } else {
                    let (n, _) = self
                        .table
                        .get(name_idx)
                        .ok_or_else(|| Error::protocol("HPACK: name index out of range"))?;
                    (Bytes::from(n), n.len())
                };
                let name = HeaderName::from_hpack_bytes(name_bytes.as_slice())?;
                let value = read_string(input, &mut pos, self.max_string_size, &self.huff)?;
                let vbytes = value.as_slice();
                let value = HeaderValue::from_bytes(vbytes)?;
                total = checked_add(total, name_len + vbytes.len())?;
                if total > self.max_header_list_size {
                    return Err(Error::overflow("HPACK: header list too large"));
                }
                // Insert into the dynamic table (only if it fits).
                self.table.dynamic().insert(name.as_bytes(), vbytes);
                out.push(HeaderField::new(name, value));
                saw_rep = true;
            } else if b & 0x20 != 0 {
                // Dynamic table size update (§6.3)
                if saw_rep {
                    return Err(Error::protocol(
                        "HPACK: size update after field representations",
                    ));
                }
                let new = read_int(input, &mut pos, 5, b & 0x1f)?;
                if new > self.max_table_size {
                    return Err(Error::protocol("HPACK: size update exceeds advertised maximum"));
                }
                self.table.dynamic().set_max_size(new);
            } else {
                // Literal without indexing (§6.2.2) or never indexed (§6.2.3)
                let never_indexed = b & 0x10 != 0;
                let name_idx = read_int(input, &mut pos, 4, b & 0x0f)?;
                let (name_bytes, name_len) = if name_idx == 0 {
                    let s = read_string(input, &mut pos, self.max_string_size, &self.huff)?;
                    let l = s.len();
                    (s, l)
                } else {
                    let (n, _) = self
                        .table
                        .get(name_idx)
                        .ok_or_else(|| Error::protocol("HPACK: name index out of range"))?;
                    (Bytes::from(n), n.len())
                };
                let name = HeaderName::from_hpack_bytes(name_bytes.as_slice())?;
                let value = read_string(input, &mut pos, self.max_string_size, &self.huff)?;
                let vbytes = value.as_slice();
                let value = HeaderValue::from_bytes(vbytes)?;
                total = checked_add(total, name_len + vbytes.len())?;
                if total > self.max_header_list_size {
                    return Err(Error::overflow("HPACK: header list too large"));
                }
                out.push(HeaderField {
                    name,
                    value,
                    never_indexed,
                });
                saw_rep = true;
            }
        }
        Ok(out)
    }
}

#[inline]
fn checked_add(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b)
        .ok_or_else(|| Error::overflow("HPACK: size arithmetic overflow"))
}

/// HPACK encoder (RFC 7541 §2 / §6). One instance per direction per
/// connection.
pub struct Encoder {
    table: Table,
    /// The maximum dynamic-table size the PEER advertised; our chosen
    /// size must never exceed it.
    peer_max_table_size: usize,
    /// Pending size update to emit at the start of the next block.
    pending_size_update: Option<usize>,
    /// Values longer than this are not indexed (table-poisoning guard).
    max_index_len: usize,
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Encoder {
    /// New encoder with the RFC default table size.
    pub fn new() -> Self {
        Self {
            table: Table::default(),
            peer_max_table_size: 4096,
            pending_size_update: None,
            max_index_len: 256,
        }
    }

    /// Apply the peer's SETTINGS_HEADER_TABLE_SIZE.
    pub fn set_peer_table_size(&mut self, size: usize) {
        self.peer_max_table_size = size;
        self.pending_size_update = Some(size);
    }

    /// Current dynamic-table occupancy (bytes).
    #[inline]
    pub fn table_size(&self) -> usize {
        self.table.size()
    }

    /// Encode a header block into `out`.
    pub fn encode(&mut self, fields: &[HeaderField], out: &mut BytesMut) {
        if let Some(new) = self.pending_size_update.take() {
            write_table_size_update(new, out);
            self.table.dynamic().set_max_size(new);
        }
        for f in fields {
            let name = f.name.as_bytes();
            let value = f.value.as_bytes();
            let sensitive = f.never_indexed || is_sensitive_name(name);

            if !sensitive {
                if let Some(idx) = self.table.find_full(name, value) {
                    // Indexed representation (§6.1)
                    write_int(0x80, 7, idx, out);
                    continue;
                }
            }

            let name_idx = self.table.find_name(name);
            let want_index = !sensitive && should_index(value, self.max_index_len);

            if sensitive {
                // Literal never indexed (§6.2.3)
                write_literal(0x10, 4, name_idx, name, value, out);
            } else if want_index {
                // Literal with incremental indexing (§6.2.1)
                write_literal(0x40, 6, name_idx, name, value, out);
                self.table.dynamic().insert(name, value);
            } else {
                // Literal without indexing (§6.2.2)
                write_literal(0x00, 4, name_idx, name, value, out);
            }
        }
    }
}

#[inline]
fn is_sensitive_name(name: &[u8]) -> bool {
    SENSITIVE_NAMES.iter().any(|s| s.as_bytes() == name)
}

/// Whether a value is worth adding to the dynamic table.
#[inline]
fn should_index(value: &[u8], max_index_len: usize) -> bool {
    !value.is_empty() && value.len() <= max_index_len
}

/// Write an integer with an `n`-bit prefix. `prefix` holds the flag bits
/// already set in the first octet (mask must be `(1<<n)-1`).
fn write_int(prefix: u8, n: u8, value: usize, out: &mut BytesMut) {
    let max_prefix = (1u16 << n) - 1;
    if (value as u16) < max_prefix {
        out.put_u8(prefix | value as u8);
        return;
    }
    out.put_u8(prefix | max_prefix as u8);
    let mut v = (value as u64) - max_prefix as u64;
    while v >= 128 {
        out.put_u8(((v % 128) as u8) | 0x80);
        v /= 128;
    }
    out.put_u8(v as u8);
}

/// Write a string literal, choosing Huffman when it shortens the output.
fn write_string(s: &[u8], out: &mut BytesMut) {
    // Measure Huffman length without emitting.
    let mut huff = Vec::with_capacity(s.len());
    huffman_encode(s, &mut huff);
    if huff.len() < s.len() {
        write_int(0x80, 7, huff.len(), out);
        out.extend_from_slice(&huff);
    } else {
        write_int(0x00, 7, s.len(), out);
        out.extend_from_slice(s);
    }
}

/// Write a literal representation with the given 2/4-bit prefix.
fn write_literal(
    prefix: u8,
    n: u8,
    name_idx: Option<usize>,
    name: &[u8],
    value: &[u8],
    out: &mut BytesMut,
) {
    match name_idx {
        Some(idx) => write_int(prefix, n, idx, out),
        None => {
            write_int(prefix, n, 0, out);
            write_string(name, out);
        }
    }
    write_string(value, out);
}

/// Write a dynamic-table size update (§6.3).
fn write_table_size_update(size: usize, out: &mut BytesMut) {
    write_int(0x20, 5, size, out);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hpack::huffman_table::HUFFMAN;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        assert!(s.len() % 2 == 0);
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }

    fn headers(list: &[(&str, &str)]) -> HeaderList {
        list.iter()
            .map(|(n, v)| {
                HeaderField::new(
                    HeaderName::from_bytes(n.as_bytes()).unwrap(),
                    HeaderValue::from_bytes(v.as_bytes()).unwrap(),
                )
            })
            .collect()
    }

    fn assert_decodes(wire: &[u8], expected: &[(&str, &str)]) {
        let mut dec = Decoder::new(4096, 1 << 20);
        let out = dec.decode(wire).unwrap();
        let exp = headers(expected);
        assert_eq!(out.len(), exp.len(), "field count");
        for (a, b) in out.iter().zip(exp.iter()) {
            assert_eq!(a.name.as_str(), b.name.as_str());
            assert_eq!(a.value.as_bytes(), b.value.as_bytes());
        }
    }

    #[test]
    fn rfc_c3_1_first_request_no_huffman() {
        // :method GET, :scheme http, :path /, :authority www.example.com
        assert_decodes(
            &hex("8286 8441 0f77 7777 2e65 7861 6d70 6c65 2e63 6f6d"),
            &[(":method", "GET"), (":scheme", "http"), (":path", "/"), (":authority", "www.example.com")],
        );
    }

    #[test]
    fn rfc_c3_2_second_request_no_huffman() {
        let mut dec = Decoder::new(4096, 1 << 20);
        let out = dec
            .decode(&hex("8286 84be 5808 6e6f 2d63 6163 6865"))
            .unwrap();
        let exp = headers(&[
            (":method", "GET"),
            (":scheme", "http"),
            (":path", "/"),
            (":authority", "www.example.com"),
            ("cache-control", "no-cache"),
        ]);
        assert_eq!(out, exp);
    }

    #[test]
    fn rfc_c3_3_third_request_no_huffman() {
        // Requires eviction (table size 256) and dynamic indexing.
        let mut dec = Decoder::new(256, 1 << 20);
        let out = dec
            .decode(&hex("8286 84be 400a 6375 7374 6f6d 2d6b 6579 0c63 7573 746f 6d2d 7661 6c75 65"))
            .unwrap();
        let exp = headers(&[
            (":method", "GET"),
            (":scheme", "https"),
            (":path", "/index.html"),
            (":authority", "www.example.com"),
            ("custom-key", "custom-value"),
        ]);
        assert_eq!(out, exp);
    }

    #[test]
    fn rfc_c4_1_first_request_huffman() {
        let mut dec = Decoder::new(4096, 1 << 20);
        let out = dec
            .decode(&hex("8286 8441 8cf1 e3c2 e5f2 3a6b a0ab 90f4 ff"))
            .unwrap();
        let exp = headers(&[
            (":method", "GET"),
            (":scheme", "http"),
            (":path", "/"),
            (":authority", "www.example.com"),
        ]);
        assert_eq!(out, exp);
    }

    #[test]
    fn rfc_c6_1_first_response_huffman() {
        let mut dec = Decoder::new(256, 1 << 20);
        let out = dec
            .decode(&hex(
                "4882 6402 5885 aec3 771a 4b61 96d0 7abe \
                 9410 54d4 44a8 2005 9504 0b81 66e0 82a6 \
                 2d1b ff6e 919d 29ad 1718 63c7 8f0b 97c8 \
                 e9ae 82ae 43d3",
            ))
            .unwrap();
        let exp = headers(&[
            (":status", "302"),
            ("cache-control", "private"),
            ("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
            ("location", "https://www.example.com"),
        ]);
        assert_eq!(out, exp);
    }

    #[test]
    fn rfc_c2_literals() {
        // C.2.1 literal indexed with new name
        let mut dec = Decoder::new(4096, 1 << 20);
        let out = dec
            .decode(&hex("400a 6375 7374 6f6d 2d6b 6579 0d63 7573 746f 6d2d 6865 6164 6572"))
            .unwrap();
        assert_eq!(
            out,
            headers(&[("custom-key", "custom-header")])
        );

        // C.2.2 literal without indexing, indexed name
        let out2 = dec
            .decode(&hex("040c 2f73 616d 706c 652f 7061 7468"))
            .unwrap();
        assert_eq!(out2, headers(&[(":path", "/sample/path")]));

        // C.2.3 literal never indexed
        let out3 = dec
            .decode(&hex("1008 7061 7373 776f 7264 0673 6563 7265 74"))
            .unwrap();
        assert_eq!(out3.len(), 1);
        assert_eq!(out3[0].name.as_str(), "password");
        assert_eq!(out3[0].value.as_bytes(), b"secret");
        assert!(out3[0].never_indexed);

        // C.2.4 indexed
        let out4 = dec.decode(&hex("82")).unwrap();
        assert_eq!(out4, headers(&[(":method", "GET")]));
    }

    #[test]
    fn huffman_table_is_complete() {
        assert_eq!(HUFFMAN.len(), 257);
        // Every length is within 5..=30 bits.
        for &(code, len) in HUFFMAN.iter() {
            assert!((5..=30).contains(&(len as u16)), "bad len {len}");
            assert!(code < (1u32 << len), "code does not fit len");
        }
    }

    #[test]
    fn encoder_decoder_roundtrip() {
        let mut enc = Encoder::new();
        let fields = headers(&[
            (":method", "GET"),
            (":scheme", "https"),
            (":path", "/index.html"),
            (":authority", "www.example.com"),
            ("accept-encoding", "gzip, deflate, br"),
            ("cache-control", "no-cache"),
        ]);
        let mut wire = BytesMut::new();
        enc.encode(&fields, &mut wire);
        let mut dec = Decoder::new(4096, 1 << 20);
        let back = dec.decode(wire.as_slice()).unwrap();
        assert_eq!(back, fields);
    }

    #[test]
    fn encoder_reuses_dynamic_table() {
        let mut enc = Encoder::new();
        let fields = headers(&[("x-foo", "bar"), ("x-foo", "bar")]);
        let mut wire = BytesMut::new();
        enc.encode(&fields, &mut wire);
        // Second occurrence should become a short indexed reference.
        let mut dec = Decoder::new(4096, 1 << 20);
        let back = dec.decode(wire.as_slice()).unwrap();
        assert_eq!(back, fields);
        assert!(wire.len() < 32, "expected compact encoding, got {} bytes", wire.len());
    }

    #[test]
    fn never_indexed_survives() {
        let mut enc = Encoder::new();
        let fields = vec![HeaderField::new_never_indexed(
            HeaderName::from_static("authorization"),
            HeaderValue::from_static("Bearer secret-token"),
        )];
        let mut wire = BytesMut::new();
        enc.encode(&fields, &mut wire);
        let mut dec = Decoder::new(4096, 1 << 20);
        let back = dec.decode(wire.as_slice()).unwrap();
        assert_eq!(back, fields);
    }

    #[test]
    fn rejects_index_zero_and_bad_update() {
        let mut dec = Decoder::new(4096, 1 << 20);
        // 0x80 -> indexed with index 0
        assert!(dec.decode(&[0x80]).is_err());
        // size update 5000 > advertised 4096
        let mut dec2 = Decoder::new(4096, 1 << 20);
        let mut wire = BytesMut::new();
        write_table_size_update(5000, &mut wire);
        assert!(dec2.decode(wire.as_slice()).is_err());
    }
}
