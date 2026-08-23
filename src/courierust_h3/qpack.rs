//! QPACK: field-line compression for HTTP/3 (RFC 9204).
//!
//! Implements the complete QPACK **codec**, verified against the RFC's
//! own worked examples (Appendix B):
//!
//! * the 99-entry static table (RFC 9204 Appendix A, **0-indexed**),
//! * prefix integers (§4.1.1) and N-bit-prefix string literals with
//!   Huffman coding (§4.1.2, shared with HPACK),
//! * the encoded-field-section prefix — Required Insert Count and Base
//!   (§4.5.1) — with the modulo arithmetic from §4.5.1.1,
//! * every field-line representation (§4.5.2–§4.5.6): indexed
//!   (static/dynamic via the `T` bit), post-base indexed, literal with
//!   name reference, literal with post-base name reference, and literal
//!   with literal name,
//! * the dynamic table with size-limited eviction (§3.2),
//! * the encoder-stream instructions (§4.3: set capacity, insert with
//!   name reference, insert with literal name, duplicate) and
//!   decoder-stream instructions (§4.4: section ack, stream
//!   cancellation, insert-count increment).
//!
//! **Scope boundary:** this is the compression layer. The built-in HTTP/3
//! runtime wires the encoder/decoder stream roles but deliberately advertises
//! zero dynamic-table capacity, so blocked field sections and dynamic-table
//! instructions are rejected rather than retained without accounting. Full
//! dynamic-table eviction coordination, blocked-stream wakeups, and section
//! acknowledgements remain outside that bounded runtime mode. The primitives
//! here are individually complete and RFC-example-tested.

use crate::courierust_error::{Error, Result};
use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// The QPACK static table (RFC 9204 Appendix A). **Indexed from 0**.
pub const STATIC_TABLE: [(&str, &str); 99] = [
    (":authority", ""),
    (":path", "/"),
    ("age", "0"),
    ("content-disposition", ""),
    ("content-length", "0"),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("referer", ""),
    ("set-cookie", ""),
    (":method", "CONNECT"),
    (":method", "DELETE"),
    (":method", "GET"),
    (":method", "HEAD"),
    (":method", "OPTIONS"),
    (":method", "POST"),
    (":method", "PUT"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "103"),
    (":status", "200"),
    (":status", "304"),
    (":status", "404"),
    (":status", "503"),
    ("accept", "*/*"),
    ("accept", "application/dns-message"),
    ("accept-encoding", "gzip, deflate, br"),
    ("accept-ranges", "bytes"),
    ("access-control-allow-headers", "cache-control"),
    ("access-control-allow-headers", "content-type"),
    ("access-control-allow-origin", "*"),
    ("cache-control", "max-age=0"),
    ("cache-control", "max-age=2592000"),
    ("cache-control", "max-age=604800"),
    ("cache-control", "no-cache"),
    ("cache-control", "no-store"),
    ("cache-control", "public, max-age=31536000"),
    ("content-encoding", "br"),
    ("content-encoding", "gzip"),
    ("content-type", "application/dns-message"),
    ("content-type", "application/javascript"),
    ("content-type", "application/json"),
    ("content-type", "application/x-www-form-urlencoded"),
    ("content-type", "image/gif"),
    ("content-type", "image/jpeg"),
    ("content-type", "image/png"),
    ("content-type", "text/css"),
    ("content-type", "text/html; charset=utf-8"),
    ("content-type", "text/plain"),
    ("content-type", "text/plain;charset=utf-8"),
    ("range", "bytes=0-"),
    ("strict-transport-security", "max-age=31536000"),
    (
        "strict-transport-security",
        "max-age=31536000; includesubdomains",
    ),
    (
        "strict-transport-security",
        "max-age=31536000; includesubdomains; preload",
    ),
    ("vary", "accept-encoding"),
    ("vary", "origin"),
    ("x-content-type-options", "nosniff"),
    ("x-xss-protection", "1; mode=block"),
    (":status", "100"),
    (":status", "204"),
    (":status", "206"),
    (":status", "302"),
    (":status", "400"),
    (":status", "403"),
    (":status", "421"),
    (":status", "425"),
    (":status", "500"),
    ("accept-language", ""),
    ("access-control-allow-credentials", "FALSE"),
    ("access-control-allow-credentials", "TRUE"),
    ("access-control-allow-headers", "*"),
    ("access-control-allow-methods", "get"),
    ("access-control-allow-methods", "get, post, options"),
    ("access-control-allow-methods", "options"),
    ("access-control-expose-headers", "content-length"),
    ("access-control-request-headers", "content-type"),
    ("access-control-request-method", "get"),
    ("access-control-request-method", "post"),
    ("alt-svc", "clear"),
    ("authorization", ""),
    (
        "content-security-policy",
        "script-src 'none'; object-src 'none'; base-uri 'none'",
    ),
    ("early-data", "1"),
    ("expect-ct", ""),
    ("forwarded", ""),
    ("if-range", ""),
    ("origin", ""),
    ("purpose", "prefetch"),
    ("server", ""),
    ("timing-allow-origin", "*"),
    ("upgrade-insecure-requests", "1"),
    ("user-agent", ""),
    ("x-forwarded-for", ""),
    ("x-frame-options", "deny"),
    ("x-frame-options", "sameorigin"),
];

/// Look up a static-table index (0-based) for an exact (name, value)
/// pair, preferring the lowest index.
pub fn static_index(name: &str, value: &str) -> Option<u64> {
    STATIC_TABLE
        .iter()
        .position(|(n, v)| *n == name && !v.is_empty() && *v == value)
        .map(|i| i as u64)
}

/// Look up a static-table index (0-based) for a name (any value).
pub fn static_name_index(name: &str) -> Option<u64> {
    STATIC_TABLE
        .iter()
        .position(|(n, _)| *n == name)
        .map(|i| i as u64)
}

// ---------------------------------------------------------------------
// Prefix integers and N-bit-prefix string literals (§4.1)
// ---------------------------------------------------------------------

/// Encode `value` as a prefix integer into `out`. `prefix_bits` is the
/// number of bits available in the first byte (1..=8); `first_byte` is
/// OR'd into the first byte (it must leave the prefix bits clear).
pub fn encode_integer(value: u64, prefix_bits: u32, first_byte: u8, out: &mut Vec<u8>) {
    let max_prefix = (1u64 << prefix_bits) - 1;
    if value < max_prefix {
        out.push(first_byte | value as u8);
        return;
    }
    out.push(first_byte | max_prefix as u8);
    let mut v = value - max_prefix;
    while v >= 128 {
        out.push((v as u8 & 0x7f) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

/// Decode a prefix integer from `buf` starting at `*pos`. Returns the
/// value; advances `*pos`.
pub fn decode_integer(buf: &[u8], prefix_bits: u32, pos: &mut usize) -> Result<u64> {
    if !(1..=8).contains(&prefix_bits) {
        return Err(Error::protocol("QPACK prefix width out of range"));
    }
    let first = *buf.get(*pos).ok_or_else(Error::eof)?;
    *pos += 1;
    let max_prefix = (1u64 << prefix_bits) - 1;
    let mut value = (first & max_prefix as u8) as u64;
    if value < max_prefix {
        return Ok(value);
    }
    let mut shift = 0u32;
    loop {
        let byte = *buf.get(*pos).ok_or_else(Error::eof)?;
        *pos += 1;
        let part = ((byte & 0x7f) as u64)
            .checked_shl(shift)
            .ok_or_else(|| Error::overflow("QPACK integer too large"))?;
        value = value
            .checked_add(part)
            .ok_or_else(|| Error::overflow("QPACK integer overflow"))?;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift = shift
            .checked_add(7)
            .ok_or_else(|| Error::overflow("QPACK integer too large"))?;
    }
}

/// Encode an N-bit-prefix string literal (RFC 9204 §4.1.2). `prefix_bits`
/// is the *total* prefix width including the Huffman flag (2..=8): the
/// Huffman flag is bit `prefix_bits - 1` and the length uses
/// `prefix_bits - 1` bits. `first_byte` carries the fixed bits above the
/// prefix. Huffman is used when it shortens the output.
pub fn encode_string(value: &[u8], prefix_bits: u8, first_byte: u8, out: &mut Vec<u8>) {
    debug_assert!((2..=8).contains(&prefix_bits));
    let mut huffman = Vec::new();
    crate::courierust_hpack::huffman::encode(value, &mut huffman);
    let use_huffman = huffman.len() < value.len();
    let (payload, hbit) = if use_huffman {
        (&huffman[..], 1u8 << (prefix_bits - 1))
    } else {
        (value, 0u8)
    };
    encode_integer(
        payload.len() as u64,
        (prefix_bits - 1) as u32,
        first_byte | hbit,
        out,
    );
    out.extend_from_slice(payload);
}

/// Decode an N-bit-prefix string literal. Returns the raw bytes
/// (Huffman-decoded when the flag was set).
pub fn decode_string(buf: &[u8], prefix_bits: u8, pos: &mut usize) -> Result<Vec<u8>> {
    debug_assert!((2..=8).contains(&prefix_bits));
    let first = *buf.get(*pos).ok_or_else(Error::eof)?;
    let huffman = first & (1u8 << (prefix_bits - 1)) != 0;
    let len = usize::try_from(decode_integer(buf, (prefix_bits - 1) as u32, pos)?)
        .map_err(|_| Error::overflow("QPACK string length does not fit usize"))?;
    let end = (*pos)
        .checked_add(len)
        .ok_or_else(|| Error::overflow("QPACK string length overflow"))?;
    if buf.len() < end {
        return Err(Error::eof());
    }
    let raw = &buf[*pos..end];
    *pos = end;
    if huffman {
        let mut out = Vec::new();
        crate::courierust_hpack::huffman::decode(raw, &mut out)
            .map_err(|_| Error::protocol("QPACK Huffman decode failed"))?;
        Ok(out)
    } else {
        Ok(raw.to_vec())
    }
}

// ---------------------------------------------------------------------
// Dynamic table (§3.2)
// ---------------------------------------------------------------------

/// A QPACK dynamic table entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynEntry {
    /// Field name.
    pub name: String,
    /// Field value.
    pub value: String,
}

/// A size-limited QPACK dynamic table.
///
/// RFC 9204 §3.2.4: absolute index 0 is the **oldest** entry and indices
/// increase with each insertion, so the table is FIFO — `entries[0]` is
/// the oldest, `entries[len-1]` is the most recent.
#[derive(Debug, Clone, Default)]
pub struct DynamicTable {
    entries: alloc::collections::VecDeque<DynEntry>,
    size: usize,
    capacity: usize,
    insert_count: u64,
}

impl DynamicTable {
    /// A table with the given capacity.
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: alloc::collections::VecDeque::new(),
            size: 0,
            capacity,
            insert_count: 0,
        }
    }

    /// Entry size: name length + value length + 32 (RFC 9204 §3.2.1).
    fn entry_size(name: &str, value: &str) -> usize {
        name.len().saturating_add(value.len()).saturating_add(32)
    }

    /// Set the table capacity, evicting oldest entries until the size
    /// fits (§3.2.2).
    pub fn set_capacity(&mut self, capacity: usize) {
        self.capacity = capacity;
        while self.size > self.capacity {
            self.evict_one();
        }
    }

    /// Current capacity.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Current size in octets.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Total inserts performed (drives insert-count arithmetic).
    pub fn insert_count(&self) -> u64 {
        self.insert_count
    }

    /// Number of entries currently held.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn evict_one(&mut self) {
        if let Some(entry) = self.entries.pop_front() {
            self.size = self
                .size
                .saturating_sub(Self::entry_size(&entry.name, &entry.value));
        }
    }

    /// Insert a (name, value) pair at the newest end, evicting from the
    /// oldest end as needed. Returns `false` when the entry is larger
    /// than the capacity (dropped per §3.2.2).
    pub fn insert(&mut self, name: &str, value: &str) -> bool {
        let entry_size = Self::entry_size(name, value);
        if entry_size > self.capacity {
            self.entries.clear();
            self.size = 0;
            return false;
        }
        while self.size.saturating_add(entry_size) > self.capacity {
            self.evict_one();
        }
        self.entries.push_back(DynEntry {
            name: name.into(),
            value: value.into(),
        });
        self.size = self.size.saturating_add(entry_size);
        self.insert_count = self.insert_count.wrapping_add(1);
        true
    }

    /// Get an entry by absolute index (0 = oldest).
    pub fn get(&self, absolute: u64) -> Option<&DynEntry> {
        let first = self.insert_count.saturating_sub(self.entries.len() as u64);
        let offset = absolute.checked_sub(first)?;
        if absolute >= self.insert_count {
            return None;
        }
        usize::try_from(offset)
            .ok()
            .and_then(|index| self.entries.get(index))
    }

    /// Absolute index of an exact (name, value) pair, newest first.
    pub fn find(&self, name: &str, value: &str) -> Option<u64> {
        let first = self.insert_count.saturating_sub(self.entries.len() as u64);
        self.entries
            .iter()
            .rposition(|e| e.name == name && e.value == value)
            .map(|i| first + i as u64)
    }

    /// Absolute index of a name (any value), newest first.
    pub fn find_name(&self, name: &str) -> Option<u64> {
        let first = self.insert_count.saturating_sub(self.entries.len() as u64);
        self.entries
            .iter()
            .rposition(|e| e.name == name)
            .map(|i| first + i as u64)
    }
}

// ---------------------------------------------------------------------
// Encoded field section prefix (§4.5.1)
// ---------------------------------------------------------------------

/// Encode the Required Insert Count + Base prefix.
///
/// `max_table_capacity` is the decoder's advertised
/// `SETTINGS_QPACK_MAX_TABLE_CAPACITY` (used to size the modulo range).
pub fn encode_field_section_prefix(
    required_insert_count: u64,
    base: u64,
    max_table_capacity: u64,
    out: &mut Vec<u8>,
) {
    let max_entries = (max_table_capacity / 32).max(1);
    let full_range = 2 * max_entries;
    let enc = if required_insert_count == 0 {
        0
    } else {
        (required_insert_count % full_range) + 1
    };
    encode_integer(enc, 8, 0, out);
    if base >= required_insert_count {
        encode_integer(base - required_insert_count, 7, 0, out);
    } else {
        encode_integer(required_insert_count - base - 1, 7, 0x80, out);
    }
}

/// Decode the Required Insert Count + Base prefix. `total_inserts` is
/// the receiver's insert count (for the modulo reconstruction in
/// §4.5.1.1).
pub fn decode_field_section_prefix(
    buf: &[u8],
    pos: &mut usize,
    total_inserts: u64,
    max_table_capacity: u64,
) -> Result<(u64, u64)> {
    let max_entries = (max_table_capacity / 32).max(1);
    let full_range = 2 * max_entries;
    let enc = decode_integer(buf, 8, pos)?;
    let first = *buf.get(*pos).ok_or_else(Error::eof)?;
    let sign = first & 0x80 != 0;
    let delta = decode_integer(buf, 7, pos)?;

    let required = if enc == 0 {
        0
    } else {
        let max_value = total_inserts
            .checked_add(max_entries)
            .ok_or_else(|| Error::overflow("QPACK insert count overflow"))?;
        let max_wrapped = (max_value / full_range) * full_range;
        let mut ric = max_wrapped
            .checked_add(enc)
            .and_then(|v| v.checked_sub(1))
            .ok_or_else(|| Error::overflow("QPACK required insert count overflow"))?;
        if ric > max_value {
            if ric <= full_range {
                return Err(Error::protocol("QPACK Required Insert Count out of range"));
            }
            ric -= full_range;
        }
        if ric == 0 {
            return Err(Error::protocol(
                "QPACK Required Insert Count wrapped to zero",
            ));
        }
        ric
    };
    let base = if sign {
        required
            .checked_sub(delta + 1)
            .ok_or_else(|| Error::protocol("QPACK negative base"))?
    } else {
        required
            .checked_add(delta)
            .ok_or_else(|| Error::overflow("QPACK base overflow"))?
    };
    Ok((required, base))
}

// ---------------------------------------------------------------------
// Field-line representations (§4.5.2–§4.5.6)
// ---------------------------------------------------------------------

/// A decoded field line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldLine {
    /// Field name (UTF-8).
    pub name: String,
    /// Field value (bytes, kept lossless).
    pub value: Vec<u8>,
    /// The never-indexed flag from the wire.
    pub never_indexed: bool,
}

/// Encode one field line. `base` is the Base of the enclosing field
/// section. Dynamic references are emitted relative to `base` (below it)
/// or as post-base references (at/above it).
pub fn encode_field_line(
    name: &str,
    value: &[u8],
    dyn_table: &DynamicTable,
    base: u64,
    out: &mut Vec<u8>,
) {
    let value_str = core::str::from_utf8(value).unwrap_or("");
    // Exact static match → indexed, T=1.
    if let Some(index) = static_index(name, value_str) {
        encode_integer(index, 6, 0xc0, out);
        return;
    }
    // Exact dynamic match.
    if let Some(abs) = dyn_table.find(name, value_str) {
        if abs < base {
            let rel = base - 1 - abs;
            encode_integer(rel, 6, 0x80, out);
        } else {
            let pbi = abs - base;
            encode_integer(pbi, 4, 0x10, out);
        }
        return;
    }
    // Static name match → literal with name reference, T=1.
    // First byte: `01` + N(0) + T(1) + 4-bit index (Figure 15).
    if let Some(index) = static_name_index(name) {
        encode_integer(index, 4, 0x50, out);
        encode_string(value, 8, 0x00, out);
        return;
    }
    // Dynamic name match.
    if let Some(abs) = dyn_table.find_name(name) {
        if abs < base {
            let rel = base - 1 - abs;
            encode_integer(rel, 4, 0x40, out);
        } else {
            let pbi = abs - base;
            encode_integer(pbi, 3, 0x00, out);
        }
        encode_string(value, 8, 0x00, out);
        return;
    }
    // Literal name: `001` + N(0) + H + 3-bit length (a 4-bit-prefix
    // string literal), then the value as an 8-bit-prefix string.
    encode_string(name.as_bytes(), 4, 0x20, out);
    encode_string(value, 8, 0x00, out);
}

/// Decode one field line. `base` is the Base of the enclosing field
/// section. The dynamic table must already hold the referenced entries
/// (connection-state responsibility).
pub fn decode_field_line(
    buf: &[u8],
    pos: &mut usize,
    dyn_table: &DynamicTable,
    base: u64,
) -> Result<FieldLine> {
    let first = *buf.get(*pos).ok_or_else(Error::eof)?;
    if first & 0x80 != 0 {
        // Indexed Field Line: `1` + T + 6-bit.
        let static_ref = first & 0x40 != 0;
        let index = decode_integer(buf, 6, pos)?;
        if static_ref {
            let (name, value) = static_entry(index)?;
            Ok(FieldLine {
                name,
                value: value.as_bytes().to_vec(),
                never_indexed: false,
            })
        } else {
            if index >= base {
                return Err(Error::protocol("QPACK dynamic relative index out of range"));
            }
            let abs = base - 1 - index;
            let entry = dyn_table
                .get(abs)
                .ok_or_else(|| Error::protocol("QPACK dynamic table entry missing"))?;
            Ok(FieldLine {
                name: entry.name.clone(),
                value: entry.value.as_bytes().to_vec(),
                never_indexed: false,
            })
        }
    } else if first & 0xc0 == 0x40 {
        // Literal Field Line with Name Reference: `01` + N + T + 4-bit
        // (N is bit 5, T is bit 4, index in the low 4 bits — Figure 15).
        let never_indexed = first & 0x20 != 0;
        let static_ref = first & 0x10 != 0;
        let index = decode_integer(buf, 4, pos)?;
        let name = if static_ref {
            STATIC_TABLE
                .get(
                    usize::try_from(index)
                        .map_err(|_| Error::overflow("QPACK static index does not fit usize"))?,
                )
                .ok_or_else(|| Error::protocol("QPACK static name index out of range"))?
                .0
                .to_string()
        } else {
            if index >= base {
                return Err(Error::protocol(
                    "QPACK dynamic name relative index out of range",
                ));
            }
            let abs = base - 1 - index;
            dyn_table
                .get(abs)
                .ok_or_else(|| Error::protocol("QPACK dynamic table entry missing"))?
                .name
                .clone()
        };
        let value = decode_string(buf, 8, pos)?;
        Ok(FieldLine {
            name,
            value,
            never_indexed,
        })
    } else if first & 0xe0 == 0x20 {
        // Literal Field Line with Literal Name: `001` + N + H + 3-bit.
        let never_indexed = first & 0x10 != 0;
        let name_raw = decode_string(buf, 4, pos)?;
        let name = String::from_utf8(name_raw)
            .map_err(|_| Error::protocol("QPACK field name is not UTF-8"))?;
        let value = decode_string(buf, 8, pos)?;
        Ok(FieldLine {
            name,
            value,
            never_indexed,
        })
    } else if first & 0xf0 == 0x10 {
        // Indexed Field Line with Post-Base Index: `0001` + 4-bit.
        let pbi = decode_integer(buf, 4, pos)?;
        let abs = base
            .checked_add(pbi)
            .ok_or_else(|| Error::overflow("QPACK post-base index overflow"))?;
        let entry = dyn_table
            .get(abs)
            .ok_or_else(|| Error::protocol("QPACK post-base index out of range"))?;
        Ok(FieldLine {
            name: entry.name.clone(),
            value: entry.value.as_bytes().to_vec(),
            never_indexed: false,
        })
    } else {
        // Literal Field Line with Post-Base Name Reference: `0000` + N +
        // 3-bit.
        let never_indexed = first & 0x10 != 0;
        let pbi = decode_integer(buf, 3, pos)?;
        let abs = base
            .checked_add(pbi)
            .ok_or_else(|| Error::overflow("QPACK post-base index overflow"))?;
        let name = dyn_table
            .get(abs)
            .ok_or_else(|| Error::protocol("QPACK post-base name index out of range"))?
            .name
            .clone();
        let value = decode_string(buf, 8, pos)?;
        Ok(FieldLine {
            name,
            value,
            never_indexed,
        })
    }
}

/// Fetch a static table entry by 0-based index.
fn static_entry(index: u64) -> Result<(String, String)> {
    let (name, value) = STATIC_TABLE
        .get(
            usize::try_from(index)
                .map_err(|_| Error::overflow("QPACK static index does not fit usize"))?,
        )
        .ok_or_else(|| Error::protocol("QPACK static index out of range"))?;
    Ok((name.to_string(), value.to_string()))
}

// ---------------------------------------------------------------------
// Encoder-stream instructions (§4.3)
// ---------------------------------------------------------------------

/// Decode and apply one encoder-stream instruction. `insert_count` is
/// the table's current insert count (for resolving dynamic relative
/// indices). `advertised_capacity` is the decoder's advertised
/// `SETTINGS_QPACK_MAX_TABLE_CAPACITY`: a Set Capacity instruction above
/// it is a QPACK_ENCODER_STREAM_ERROR (RFC 9204 §4.3.1).
pub fn decode_encoder_instruction(
    buf: &[u8],
    pos: &mut usize,
    dyn_table: &mut DynamicTable,
    insert_count: u64,
    advertised_capacity: Option<u64>,
) -> Result<()> {
    let first = *buf.get(*pos).ok_or_else(Error::eof)?;
    if first & 0x80 != 0 {
        // Insert with Name Reference: `1` + T + 6-bit.
        let static_ref = first & 0x40 != 0;
        let index = decode_integer(buf, 6, pos)?;
        let value = decode_string(buf, 8, pos)?;
        let value_str =
            String::from_utf8(value).map_err(|_| Error::protocol("QPACK value is not UTF-8"))?;
        let name = if static_ref {
            STATIC_TABLE
                .get(
                    usize::try_from(index)
                        .map_err(|_| Error::overflow("QPACK static index does not fit usize"))?,
                )
                .ok_or_else(|| Error::protocol("QPACK static index out of range"))?
                .0
                .to_string()
        } else {
            if index >= insert_count {
                return Err(Error::protocol("QPACK dynamic reference out of range"));
            }
            let abs = insert_count - 1 - index;
            dyn_table
                .get(abs)
                .ok_or_else(|| Error::protocol("QPACK dynamic table entry missing"))?
                .name
                .clone()
        };
        dyn_table.insert(&name, &value_str);
        return Ok(());
    }
    if first & 0xc0 == 0x40 {
        // Insert with Literal Name: `01` + H + 5-bit (6-bit-prefix
        // string), then 8-bit-prefix value string.
        let name_raw = decode_string(buf, 6, pos)?;
        let name = String::from_utf8(name_raw)
            .map_err(|_| Error::protocol("QPACK field name is not UTF-8"))?;
        let value = decode_string(buf, 8, pos)?;
        let value_str =
            String::from_utf8(value).map_err(|_| Error::protocol("QPACK value is not UTF-8"))?;
        dyn_table.insert(&name, &value_str);
        return Ok(());
    }
    if first & 0xe0 == 0x20 {
        // Set Dynamic Table Capacity: `001` + 5-bit. MUST NOT exceed the
        // decoder's advertised capacity (RFC 9204 §4.3.1).
        let capacity = decode_integer(buf, 5, pos)?;
        if advertised_capacity.is_some_and(|advertised| capacity > advertised) {
            return Err(Error::protocol(
                "QPACK Set Capacity exceeds the advertised maximum",
            ));
        }
        dyn_table.set_capacity(
            usize::try_from(capacity)
                .map_err(|_| Error::overflow("QPACK table capacity does not fit usize"))?,
        );
        return Ok(());
    }
    // Duplicate: `000` + 5-bit relative index.
    let index = decode_integer(buf, 5, pos)?;
    if index >= insert_count {
        return Err(Error::protocol("QPACK duplicate index out of range"));
    }
    let abs = insert_count - 1 - index;
    let entry = dyn_table
        .get(abs)
        .ok_or_else(|| Error::protocol("QPACK dynamic table entry missing"))?
        .clone();
    dyn_table.insert(&entry.name, &entry.value);
    Ok(())
}

/// An encoder-stream instruction to emit (RFC 9204 §4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncoderInstruction<'a> {
    /// Set the dynamic table capacity (`001` + 5-bit).
    SetCapacity(u64),
    /// Insert with name reference (`1` + T + 6-bit + value).
    InsertWithNameRef {
        /// Whether the referenced name is in the static table.
        static_ref: bool,
        /// Static index, or dynamic relative index (current inserts).
        index: u64,
        /// Field value.
        value: &'a [u8],
    },
    /// Insert with literal name (`01` + name + value).
    InsertWithLiteralName {
        /// Field name.
        name: &'a [u8],
        /// Field value.
        value: &'a [u8],
    },
    /// Duplicate the entry at the given relative index (`000` + 5-bit).
    Duplicate(u64),
}

/// Encode an encoder-stream instruction (RFC 9204 §4.3).
pub fn encode_encoder_instruction(instruction: &EncoderInstruction, out: &mut Vec<u8>) {
    match instruction {
        EncoderInstruction::SetCapacity(capacity) => {
            encode_integer(*capacity, 5, 0x20, out);
        }
        EncoderInstruction::InsertWithNameRef {
            static_ref,
            index,
            value,
        } => {
            let first = if *static_ref { 0xc0 } else { 0x80 };
            encode_integer(*index, 6, first, out);
            encode_string(value, 8, 0x00, out);
        }
        EncoderInstruction::InsertWithLiteralName { name, value } => {
            encode_string(name, 6, 0x40, out);
            encode_string(value, 8, 0x00, out);
        }
        EncoderInstruction::Duplicate(index) => {
            encode_integer(*index, 5, 0x00, out);
        }
    }
}

// ---------------------------------------------------------------------
// Decoder-stream instructions (§4.4)
// ---------------------------------------------------------------------

/// A decoder-stream instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecoderInstruction {
    /// Section acknowledgment (stream id).
    SectionAck(u64),
    /// Stream cancellation (stream id).
    StreamCancellation(u64),
    /// Insert count increment.
    InsertCountIncrement(u64),
}

/// Encode a decoder-stream instruction.
pub fn encode_decoder_instruction(instruction: &DecoderInstruction, out: &mut Vec<u8>) {
    match instruction {
        DecoderInstruction::SectionAck(stream_id) => {
            encode_integer(*stream_id, 7, 0x80, out);
        }
        DecoderInstruction::StreamCancellation(stream_id) => {
            encode_integer(*stream_id, 6, 0x40, out);
        }
        DecoderInstruction::InsertCountIncrement(increment) => {
            encode_integer(*increment, 6, 0x00, out);
        }
    }
}

/// Decode one decoder-stream instruction.
pub fn decode_decoder_instruction(buf: &[u8], pos: &mut usize) -> Result<DecoderInstruction> {
    let first = *buf.get(*pos).ok_or_else(Error::eof)?;
    if first & 0x80 != 0 {
        let stream_id = decode_integer(buf, 7, pos)?;
        Ok(DecoderInstruction::SectionAck(stream_id))
    } else if first & 0xc0 == 0x40 {
        let stream_id = decode_integer(buf, 6, pos)?;
        Ok(DecoderInstruction::StreamCancellation(stream_id))
    } else {
        let increment = decode_integer(buf, 6, pos)?;
        Ok(DecoderInstruction::InsertCountIncrement(increment))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_table_matches_appendix_a() {
        assert_eq!(STATIC_TABLE.len(), 99);
        // Spot-check the 0-based indices against RFC 9204 Appendix A.
        assert_eq!(STATIC_TABLE[0], (":authority", ""));
        assert_eq!(STATIC_TABLE[1], (":path", "/"));
        assert_eq!(STATIC_TABLE[24], (":status", "103"));
        assert_eq!(STATIC_TABLE[25], (":status", "200"));
        assert_eq!(static_index(":status", "200"), Some(25));
        assert_eq!(static_index(":status", "201"), None);
        assert_eq!(static_name_index("content-length"), Some(4));
    }

    #[test]
    fn integer_round_trip_prefixes() {
        for prefix in [1u32, 3, 4, 5, 6, 7, 8] {
            for value in [0u64, 1, 10, 100, 1000, 16384, 1 << 20, 1 << 40] {
                let mut out = Vec::new();
                encode_integer(value, prefix, 0, &mut out);
                let mut pos = 0;
                assert_eq!(decode_integer(&out, prefix, &mut pos).unwrap(), value);
                assert_eq!(pos, out.len());
            }
        }
    }

    #[test]
    fn string_round_trip_all_prefixes() {
        for prefix in [4u8, 6, 8] {
            for value in [b"".as_slice(), b"hello", b"a", &[0u8, 255, 128]] {
                let mut out = Vec::new();
                encode_string(value, prefix, 0, &mut out);
                let mut pos = 0;
                assert_eq!(decode_string(&out, prefix, &mut pos).unwrap(), value);
                assert_eq!(pos, out.len());
            }
        }
    }

    #[test]
    fn rfc_appendix_b1_literal_name_reference() {
        // RFC 9204 B.1: Required Insert Count = 0, Base = 0, then a
        // literal field line with static name reference, index 1
        // (:path=/index.html). The wire is `00 51 0b 2f69 6e64 6578 2e68
        // 746d 6c`.
        let wire: Vec<u8> = vec![
            0x00, // Required Insert Count = 0
            0x00, // Base = 0 (S=0, Delta=0)
            0x51, // Literal name reference, T=1, index 1 (0x48|1 = 0x49? no: 0x51 = 0x40|0x10|1)
            0x0b, 0x2f, 0x69, 0x6e, 0x64, 0x65, 0x78, 0x2e, 0x68, 0x74, 0x6d,
            0x6c, // "/index.html"
        ];
        let mut pos = 0;
        let (required, base) = decode_field_section_prefix(&wire, &mut pos, 0, 0).unwrap();
        assert_eq!((required, base), (0, 0));
        let line = decode_field_line(&wire, &mut pos, &DynamicTable::new(0), base).unwrap();
        assert_eq!(line.name, ":path");
        assert_eq!(line.value, b"/index.html");
        assert_eq!(pos, wire.len());
    }

    #[test]
    fn rfc_appendix_b2_dynamic_table() {
        // Encoder stream: set capacity 220, insert :authority and :path.
        let mut table = DynamicTable::new(0);
        // 3f bd 01 = Set Dynamic Table Capacity (5-bit prefix) = 220.
        let mut enc: Vec<u8> = vec![0x3f, 0xbd, 0x01];
        // c0 0f "www.example.com" = Insert With Name Reference, T=1,
        // index 0 (:authority).
        enc.extend_from_slice(&[0xc0, 0x0f]);
        enc.extend_from_slice(b"www.example.com");
        // c1 0c "/sample/path" = Insert With Name Reference, T=1, index 1
        // (:path).
        enc.extend_from_slice(&[0xc1, 0x0c]);
        enc.extend_from_slice(b"/sample/path");

        let mut pos = 0;
        while pos < enc.len() {
            let insert_count = table.insert_count();
            decode_encoder_instruction(&enc, &mut pos, &mut table, insert_count, Some(220))
                .unwrap();
        }
        assert_eq!(table.insert_count(), 2);
        assert_eq!(table.get(0).unwrap().name, ":authority");
        assert_eq!(table.get(0).unwrap().value, "www.example.com");
        assert_eq!(table.get(1).unwrap().name, ":path");
        assert_eq!(table.get(1).unwrap().value, "/sample/path");

        // Field section on stream 4: `03 81 10 11`.
        // Required Insert Count encoded = 3 → RIC = 2 (mod range).
        // Base byte 0x81: S=1, Delta=1 → Base = 2 - 1 - 1 = 0.
        // 0x10 = post-base indexed, pbi 0 → abs 0 (:authority).
        // 0x11 = post-base indexed, pbi 1 → abs 1 (:path).
        let section: Vec<u8> = vec![0x03, 0x81, 0x10, 0x11];
        let mut pos = 0;
        let (required, base) =
            decode_field_section_prefix(&section, &mut pos, table.insert_count(), 220).unwrap();
        assert_eq!(required, 2, "RFC 9204 B.2 Required Insert Count");
        assert_eq!(base, 0, "RFC 9204 B.2 Base");
        let l1 = decode_field_line(&section, &mut pos, &table, base).unwrap();
        assert_eq!(
            (l1.name.as_str(), l1.value.as_slice()),
            (":authority", b"www.example.com".as_slice())
        );
        let l2 = decode_field_line(&section, &mut pos, &table, base).unwrap();
        assert_eq!(
            (l2.name.as_str(), l2.value.as_slice()),
            (":path", b"/sample/path".as_slice())
        );
        assert_eq!(pos, section.len());
    }

    #[test]
    fn rfc_appendix_b3_speculative_insert() {
        // Encoder: Insert With Literal Name: 4a = 0x40 | 0x20 | 0x0a
        // (H bit set, 5-bit length 10), then Huffman of "custom-key",
        // then 0x0c + "custom-value".
        let mut enc: Vec<u8> = Vec::new();
        encode_string(b"custom-key", 6, 0x40, &mut enc);
        encode_string(b"custom-value", 8, 0x00, &mut enc);
        let mut table = DynamicTable::new(1000);
        let mut pos = 0;
        decode_encoder_instruction(&enc, &mut pos, &mut table, 0, Some(220)).unwrap();
        assert_eq!(pos, enc.len());
        assert_eq!(table.insert_count(), 1);
        assert_eq!(table.get(0).unwrap().name, "custom-key");
        assert_eq!(table.get(0).unwrap().value, "custom-value");
        // Decoder: Insert Count Increment (1) = `01`.
        let mut pos = 0;
        assert_eq!(
            decode_decoder_instruction(&[0x01], &mut pos).unwrap(),
            DecoderInstruction::InsertCountIncrement(1)
        );
        assert_eq!(pos, 1);
    }

    #[test]
    fn rfc_appendix_b4_duplicate_and_cancellation() {
        let mut table = DynamicTable::new(1000);
        table.insert(":authority", "www.example.com");
        table.insert(":path", "/sample/path");
        table.insert("custom-key", "custom-value");
        assert_eq!(table.insert_count(), 3);

        // Duplicate (relative index 2) = `02` → abs = 3 - 1 - 2 = 0.
        let mut pos = 0;
        let insert_count = table.insert_count();
        decode_encoder_instruction(&[0x02], &mut pos, &mut table, insert_count, Some(220)).unwrap();
        assert_eq!(table.insert_count(), 4);
        assert_eq!(table.get(3).unwrap().name, ":authority");

        // Field section: Required Insert Count = 4, Base = 4 → prefix
        // `05 00`, then `80` = indexed dynamic rel 0 → abs = 4-1-0 = 3
        // (:authority), `c1` = indexed static index 1 (:path=/), `81` =
        // indexed dynamic rel 1 → abs = 4-1-1 = 2 (custom-key).
        let section: Vec<u8> = vec![0x05, 0x00, 0x80, 0xc1, 0x81];
        let mut pos = 0;
        let (required, base) =
            decode_field_section_prefix(&section, &mut pos, table.insert_count(), 220).unwrap();
        assert_eq!((required, base), (4, 4));
        let l1 = decode_field_line(&section, &mut pos, &table, base).unwrap();
        assert_eq!(
            (l1.name.as_str(), l1.value.as_slice()),
            (":authority", b"www.example.com".as_slice())
        );
        let l2 = decode_field_line(&section, &mut pos, &table, base).unwrap();
        assert_eq!(
            (l2.name.as_str(), l2.value.as_slice()),
            (":path", b"/".as_slice())
        );
        let l3 = decode_field_line(&section, &mut pos, &table, base).unwrap();
        assert_eq!(
            (l3.name.as_str(), l3.value.as_slice()),
            ("custom-key", b"custom-value".as_slice())
        );

        // Stream Cancellation (stream=8) = `48`.
        let mut pos = 0;
        assert_eq!(
            decode_decoder_instruction(&[0x48], &mut pos).unwrap(),
            DecoderInstruction::StreamCancellation(8)
        );
    }

    #[test]
    fn dynamic_table_eviction() {
        let mut table = DynamicTable::new(1000);
        table.insert("aaaa", "a");
        table.insert("bbbb", "b");
        assert_eq!(table.len(), 2);
        // Shrink so only the newest entry fits: size = 4 + 1 + 32.
        table.set_capacity(4 + 1 + 32);
        assert_eq!(table.len(), 1);
        // Absolute index 0 was evicted; the newest entry is index 1.
        assert_eq!(table.get(1).unwrap().name, "bbbb");
    }

    #[test]
    fn prefix_round_trip() {
        for (ric, base) in [(0u64, 0u64), (2, 0), (9, 6), (4, 4), (1, 3)] {
            let mut out = Vec::new();
            encode_field_section_prefix(ric, base, 220, &mut out);
            let mut pos = 0;
            // The receiver's insert count must be consistent with the
            // sender's table state for the modulo reconstruction.
            let (dric, dbase) = decode_field_section_prefix(&out, &mut pos, ric, 220).unwrap();
            assert_eq!((dric, dbase), (ric, base), "RIC={ric} Base={base}");
            assert_eq!(pos, out.len());
        }
    }
}
