//! HPACK indexing tables: the RFC 7541 static table and the per-context
//! dynamic table, combined into one index address space.
//!
//! Lookups are hash-accelerated: each entry carries an FNV-1a hash of its
//! name, so a name search only compares bytes when hashes agree.

use crate::bytes::Bytes;
use alloc::collections::VecDeque;
use alloc::vec::Vec;

/// FNV-1a 64-bit hash (public-domain algorithm, Fowler/Noll/Vo).
pub(crate) const fn fnv1a(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    let mut i = 0;
    while i < data.len() {
        h ^= data[i] as u64;
        h = h.wrapping_mul(0x100000001b3);
        i += 1;
    }
    h
}

/// RFC 7541 Appendix A static table, index 1..=61.
pub const STATIC_TABLE: [(&[u8], &[u8]); 61] = [
    (b":authority", b""),
    (b":method", b"GET"),
    (b":method", b"POST"),
    (b":path", b"/"),
    (b":path", b"/index.html"),
    (b":scheme", b"http"),
    (b":scheme", b"https"),
    (b":status", b"200"),
    (b":status", b"204"),
    (b":status", b"206"),
    (b":status", b"304"),
    (b":status", b"400"),
    (b":status", b"404"),
    (b":status", b"500"),
    (b"accept-charset", b""),
    (b"accept-encoding", b"gzip, deflate"),
    (b"accept-language", b""),
    (b"accept-ranges", b""),
    (b"accept", b""),
    (b"access-control-allow-origin", b""),
    (b"age", b""),
    (b"allow", b""),
    (b"authorization", b""),
    (b"cache-control", b""),
    (b"content-disposition", b""),
    (b"content-encoding", b""),
    (b"content-language", b""),
    (b"content-length", b""),
    (b"content-location", b""),
    (b"content-range", b""),
    (b"content-type", b""),
    (b"cookie", b""),
    (b"date", b""),
    (b"etag", b""),
    (b"expect", b""),
    (b"expires", b""),
    (b"from", b""),
    (b"host", b""),
    (b"if-match", b""),
    (b"if-modified-since", b""),
    (b"if-none-match", b""),
    (b"if-range", b""),
    (b"if-unmodified-since", b""),
    (b"last-modified", b""),
    (b"link", b""),
    (b"location", b""),
    (b"max-forwards", b""),
    (b"proxy-authenticate", b""),
    (b"proxy-authorization", b""),
    (b"range", b""),
    (b"referer", b""),
    (b"refresh", b""),
    (b"retry-after", b""),
    (b"server", b""),
    (b"set-cookie", b""),
    (b"strict-transport-security", b""),
    (b"transfer-encoding", b""),
    (b"user-agent", b""),
    (b"vary", b""),
    (b"via", b""),
    (b"www-authenticate", b""),
];

/// Precomputed name hashes for the static table.
pub(crate) const STATIC_NAME_HASH: [u64; 61] = {
    let mut out = [0u64; 61];
    let mut i = 0;
    while i < STATIC_TABLE.len() {
        out[i] = fnv1a(STATIC_TABLE[i].0);
        i += 1;
    }
    out
};

/// Number of static-table entries.
pub const STATIC_LEN: usize = STATIC_TABLE.len();

#[derive(Clone)]
struct DynEntry {
    name: Bytes,
    value: Bytes,
    hash: u64,
    size: usize,
}

/// The per-context dynamic table (RFC 7541 §2.3.2 / §4).
#[derive(Clone)]
pub struct DynamicTable {
    entries: VecDeque<DynEntry>,
    size: usize,
    max_size: usize,
}

impl Default for DynamicTable {
    fn default() -> Self {
        Self {
            entries: VecDeque::new(),
            size: 0,
            max_size: 4096,
        }
    }
}

impl DynamicTable {
    /// Current occupied size in octets.
    #[inline]
    pub fn size(&self) -> usize {
        self.size
    }

    /// Current capacity.
    #[inline]
    pub fn max_size(&self) -> usize {
        self.max_size
    }

    /// Number of entries.
    #[inline]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Change the capacity, evicting from the tail as needed.
    pub fn set_max_size(&mut self, max: usize) {
        self.max_size = max;
        self.evict_to(self.max_size);
    }

    /// Evict entries until the table fits within `budget`.
    fn evict_to(&mut self, budget: usize) {
        while self.size > budget && !self.entries.is_empty() {
            if let Some(e) = self.entries.pop_back() {
                self.size -= e.size;
            }
        }
    }

    /// Insert a header field at the front, evicting as needed.
    /// An entry larger than `max_size` empties the table and is not
    /// inserted (RFC 7541 §4.4).
    pub fn insert(&mut self, name: &[u8], value: &[u8]) {
        let entry_size = name.len() + value.len() + 32;
        if entry_size > self.max_size {
            self.clear();
            return;
        }
        self.evict_to(self.max_size.saturating_sub(entry_size));
        self.entries.push_front(DynEntry {
            name: Bytes::from(name),
            value: Bytes::from(value),
            hash: fnv1a(name),
            size: entry_size,
        });
        self.size += entry_size;
    }

    /// Remove everything (used when table size drops to 0).
    pub fn clear(&mut self) {
        self.entries.clear();
        self.size = 0;
    }

    /// Get the 0-based dynamic entry at `i`.
    #[inline]
    pub fn get(&self, i: usize) -> Option<(&[u8], &[u8])> {
        self.entries.get(i).map(|e| (e.name.as_slice(), e.value.as_slice()))
    }

    /// Find a dynamic entry with matching name AND value. Returns the
    /// 0-based dynamic index (0 = newest).
    pub fn find_full(&self, name: &[u8], value: &[u8]) -> Option<usize> {
        let h = fnv1a(name);
        for (i, e) in self.entries.iter().enumerate() {
            if e.hash == h && e.name.as_slice() == name && e.value.as_slice() == value {
                return Some(i);
            }
        }
        None
    }

    /// Find a dynamic entry with matching name (newest first). Returns
    /// the 0-based dynamic index.
    pub fn find_name(&self, name: &[u8]) -> Option<usize> {
        let h = fnv1a(name);
        for (i, e) in self.entries.iter().enumerate() {
            if e.hash == h && e.name.as_slice() == name {
                return Some(i);
            }
        }
        None
    }
}

/// Combined static + dynamic table with 1-based global indexing.
#[derive(Clone)]
pub struct Table {
    dyn_table: DynamicTable,
}

impl Default for Table {
    fn default() -> Self {
        Self {
            dyn_table: DynamicTable::default(),
        }
    }
}

impl Table {
    /// The dynamic sub-table.
    #[inline]
    pub fn dynamic(&mut self) -> &mut DynamicTable {
        &mut self.dyn_table
    }

    /// Resolve a 1-based global index into a header field.
    pub fn get(&self, index: usize) -> Option<(&[u8], &[u8])> {
        if (1..=STATIC_LEN).contains(&index) {
            Some(STATIC_TABLE[index - 1])
        } else {
            let d = index - STATIC_LEN - 1;
            self.dyn_table.get(d)
        }
    }

    /// Look up a name-only match. Returns the 1-based global index.
    /// Prefers the dynamic table (RFC 7541: dynamic indices are cheaper
    /// for the decoder) then the static table.
    pub fn find_name(&self, name: &[u8]) -> Option<usize> {
        if let Some(d) = self.dyn_table.find_name(name) {
            return Some(STATIC_LEN + 1 + d);
        }
        let h = fnv1a(name);
        for (i, (n, _)) in STATIC_TABLE.iter().enumerate() {
            if STATIC_NAME_HASH[i] == h && *n == name {
                return Some(i + 1);
            }
        }
        None
    }

    /// Look up an exact name+value match. Returns the 1-based global
    /// index. Prefers the dynamic table, then the static table.
    pub fn find_full(&self, name: &[u8], value: &[u8]) -> Option<usize> {
        if let Some(d) = self.dyn_table.find_full(name, value) {
            return Some(STATIC_LEN + 1 + d);
        }
        let h = fnv1a(name);
        for (i, (n, v)) in STATIC_TABLE.iter().enumerate() {
            if STATIC_NAME_HASH[i] == h && *n == name && *v == value {
                return Some(i + 1);
            }
        }
        None
    }

    /// Current total dynamic size.
    #[inline]
    pub fn size(&self) -> usize {
        self.dyn_table.size()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_indices() {
        assert_eq!(Table::default().get(1), Some((b":authority".as_slice(), b"".as_slice())));
        assert_eq!(Table::default().get(2), Some((b":method".as_slice(), b"GET".as_slice())));
        assert_eq!(Table::default().get(61), Some((b"www-authenticate".as_slice(), b"".as_slice())));
        assert_eq!(Table::default().get(62), None);
        assert_eq!(Table::default().get(0), None);
    }

    #[test]
    fn dynamic_insert_evict_and_find() {
        let mut t = Table::default();
        t.dynamic().set_max_size(100);
        t.dynamic().insert(b":authority", b"www.example.com"); // size 57
        assert_eq!(t.dynamic().size(), 57);
        // 57 + 53 (cache-control: no-cache) = 110 > 100 -> evict :authority
        t.dynamic().insert(b"cache-control", b"no-cache");
        assert_eq!(t.dynamic().len(), 1);
        // global index of newest dynamic entry = 62
        assert_eq!(t.find_full(b"cache-control", b"no-cache"), Some(62));
        assert_eq!(t.find_name(b"cache-control"), Some(62));
        assert_eq!(t.find_name(b":method"), Some(2));
    }

    #[test]
    fn oversized_entry_empties() {
        let mut t = Table::default();
        t.dynamic().set_max_size(64);
        t.dynamic().insert(b"a", b"b");
        assert_eq!(t.dynamic().len(), 1);
        let big = vec![b'x'; 100];
        t.dynamic().insert(&big, &big);
        assert_eq!(t.dynamic().len(), 0);
    }
}
