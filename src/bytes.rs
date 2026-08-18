//! Cheap immutable byte buffer and a growable write buffer.
//!
//! [`Bytes`] is an immutable, `Arc`-backed slice with O(1) slicing and
//! cheap clone — the currency of frame payloads and header values.
//! [`BytesMut`] is the growable builder used by encoders.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::ops::Deref;

/// Immutable byte buffer with O(1) slicing and cheap clone.
#[derive(Clone, Default)]
pub struct Bytes {
    buf: Arc<[u8]>,
    start: usize,
    len: usize,
}

impl Bytes {
    /// Empty buffer.
    #[inline]
    pub fn new() -> Self {
        Self {
            buf: Arc::from(&[][..]),
            start: 0,
            len: 0,
        }
    }

    /// Buffer from a static slice (no allocation).
    #[inline]
    pub fn from_static(s: &'static [u8]) -> Self {
        Self {
            buf: Arc::from(s),
            start: 0,
            len: s.len(),
        }
    }

    /// Number of bytes.
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the buffer is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// O(1) sub-slice.
    #[inline]
    pub fn slice(&self, range: Range<usize>) -> Self {
        assert!(range.start <= range.end && range.end <= self.len);
        Self {
            buf: self.buf.clone(),
            start: self.start + range.start,
            len: range.end - range.start,
        }
    }

    /// O(1) suffix.
    #[inline]
    pub fn slice_from(&self, from: usize) -> Self {
        assert!(from <= self.len);
        Self {
            buf: self.buf.clone(),
            start: self.start + from,
            len: self.len - from,
        }
    }

    /// O(1) prefix.
    #[inline]
    pub fn slice_to(&self, to: usize) -> Self {
        assert!(to <= self.len);
        Self {
            buf: self.buf.clone(),
            start: self.start,
            len: to,
        }
    }

    /// Split off the first `at` bytes, returning them and keeping the rest.
    #[inline]
    pub fn split_to(&mut self, at: usize) -> Self {
        assert!(at <= self.len);
        let out = Self {
            buf: self.buf.clone(),
            start: self.start,
            len: at,
        };
        self.start += at;
        self.len -= at;
        out
    }

    /// Split off the tail starting at `at`, returning the tail.
    #[inline]
    pub fn split_off(&mut self, at: usize) -> Self {
        assert!(at <= self.len);
        let out = Self {
            buf: self.buf.clone(),
            start: self.start + at,
            len: self.len - at,
        };
        self.len = at;
        out
    }

    /// The underlying contiguous slice.
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.buf[self.start..self.start + self.len]
    }

    /// Copy into a fresh `Vec`.
    #[inline]
    pub fn to_vec(&self) -> Vec<u8> {
        self.as_slice().to_vec()
    }

    /// Copy into a fresh owned buffer.
    #[inline]
    pub fn into_vec(self) -> Vec<u8> {
        self.to_vec()
    }

    /// View as `str` if valid UTF-8.
    #[inline]
    pub fn to_str(&self) -> Result<&str, core::str::Utf8Error> {
        core::str::from_utf8(self.as_slice())
    }
}

impl Deref for Bytes {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl AsRef<[u8]> for Bytes {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl From<Vec<u8>> for Bytes {
    #[inline]
    fn from(v: Vec<u8>) -> Self {
        let len = v.len();
        Self {
            buf: Arc::from(v.into_boxed_slice()),
            start: 0,
            len,
        }
    }
}

impl From<Box<[u8]>> for Bytes {
    #[inline]
    fn from(b: Box<[u8]>) -> Self {
        let len = b.len();
        Self {
            buf: Arc::from(b),
            start: 0,
            len,
        }
    }
}

impl From<&[u8]> for Bytes {
    #[inline]
    fn from(s: &[u8]) -> Self {
        Self::from(s.to_vec())
    }
}

impl From<&str> for Bytes {
    #[inline]
    fn from(s: &str) -> Self {
        Self::from(s.as_bytes())
    }
}

impl From<String> for Bytes {
    #[inline]
    fn from(s: String) -> Self {
        Self::from(s.into_bytes())
    }
}

impl PartialEq for Bytes {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl Eq for Bytes {}

impl PartialEq<[u8]> for Bytes {
    #[inline]
    fn eq(&self, other: &[u8]) -> bool {
        self.as_slice() == other
    }
}

impl PartialEq<str> for Bytes {
    #[inline]
    fn eq(&self, other: &str) -> bool {
        self.as_slice() == other.as_bytes()
    }
}

impl PartialOrd for Bytes {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Bytes {
    #[inline]
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.as_slice().cmp(other.as_slice())
    }
}

impl core::hash::Hash for Bytes {
    #[inline]
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.as_slice().hash(state)
    }
}

impl fmt::Debug for Bytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Bytes(len={})", self.len)
    }
}

impl fmt::Display for Bytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match core::str::from_utf8(self.as_slice()) {
            Ok(s) => f.write_str(s),
            Err(_) => write!(f, "<invalid utf8, {} bytes>", self.len),
        }
    }
}

/// Growable byte builder, the counterpart of [`Bytes`].
#[derive(Clone, Default)]
pub struct BytesMut {
    buf: Vec<u8>,
}

impl BytesMut {
    /// Empty buffer.
    #[inline]
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Empty buffer with capacity.
    #[inline]
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            buf: Vec::with_capacity(cap),
        }
    }

    /// From an existing `Vec` (takes ownership).
    #[inline]
    pub fn from_vec(v: Vec<u8>) -> Self {
        Self { buf: v }
    }

    /// Number of bytes.
    #[inline]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Whether empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Contiguous view.
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    /// Mutable contiguous view.
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.buf
    }

    /// Clear without releasing capacity.
    #[inline]
    pub fn clear(&mut self) {
        self.buf.clear();
    }

    /// Reserve capacity.
    #[inline]
    pub fn reserve(&mut self, extra: usize) {
        self.buf.reserve(extra);
    }

    /// Append a slice.
    #[inline]
    pub fn extend_from_slice(&mut self, s: &[u8]) {
        self.buf.extend_from_slice(s);
    }

    /// Append an iterator of slices (avoids re-borrowing).
    #[inline]
    pub fn extend_from_slices<'a>(&mut self, slices: impl IntoIterator<Item = &'a [u8]>) {
        for s in slices {
            self.buf.extend_from_slice(s);
        }
    }

    /// Append a single byte.
    #[inline]
    pub fn put_u8(&mut self, b: u8) {
        self.buf.push(b);
    }

    /// Append a big-endian u16.
    #[inline]
    pub fn put_u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    /// Append a big-endian 24-bit value.
    #[inline]
    pub fn put_u24(&mut self, v: u32) {
        debug_assert!(v <= 0xFF_FFFF);
        self.buf.push((v >> 16) as u8);
        self.buf.push((v >> 8) as u8);
        self.buf.push(v as u8);
    }

    /// Append a big-endian u32.
    #[inline]
    pub fn put_u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    /// Append a big-endian u64.
    #[inline]
    pub fn put_u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    /// Append another buffer.
    #[inline]
    pub fn put_bytes(&mut self, b: &Bytes) {
        self.buf.extend_from_slice(b.as_slice());
    }

    /// Turn into an immutable [`Bytes`] (copies; callers needing O(1)
    /// should keep a [`BytesMut`] and freeze rarely).
    #[inline]
    pub fn freeze(self) -> Bytes {
        Bytes::from(self.buf)
    }

    /// Truncate to `len`.
    #[inline]
    pub fn truncate(&mut self, len: usize) {
        self.buf.truncate(len);
    }

    /// Split off the tail starting at `at`.
    #[inline]
    pub fn split_off(&mut self, at: usize) -> BytesMut {
        BytesMut {
            buf: self.buf.split_off(at),
        }
    }

    /// Steal the inner `Vec`.
    #[inline]
    pub fn into_vec(self) -> Vec<u8> {
        self.buf
    }
}

impl Deref for BytesMut {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &[u8] {
        &self.buf
    }
}

impl AsRef<[u8]> for BytesMut {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.buf
    }
}

impl fmt::Debug for BytesMut {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BytesMut(len={})", self.buf.len())
    }
}
