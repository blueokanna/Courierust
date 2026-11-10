//! Cheap immutable byte buffer and a growable write buffer.
//!
//! [`Bytes`] is an immutable, reference-counted or static slice with O(1) slicing and
//! cheap clone — the currency of frame payloads and header values.
//! [`BytesMut`] is the growable builder used by encoders.

use crate::shared::Shared;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::ops::{Deref, Range};

/// Immutable byte buffer with O(1) slicing and cheap clone.
///
/// Static buffers borrow their input. Owned buffers share a `Vec` without
/// copying its allocation. Sharing uses `Arc` on targets with pointer atomics
/// and `Rc` otherwise; on the latter, `Bytes` is neither `Send` nor `Sync`.
#[derive(Clone)]
pub struct Bytes {
    storage: Storage,
}

#[derive(Clone)]
enum Storage {
    Static(&'static [u8]),
    Shared {
        buf: Shared<Vec<u8>>,
        start: usize,
        len: usize,
    },
}

impl Default for Bytes {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl Bytes {
    /// Empty buffer. Does not allocate.
    #[inline]
    pub const fn new() -> Self {
        Self::from_static(&[])
    }

    /// Borrow a static slice without allocation or copying.
    #[inline]
    pub const fn from_static(s: &'static [u8]) -> Self {
        Self {
            storage: Storage::Static(s),
        }
    }

    /// Number of bytes.
    #[inline]
    pub fn len(&self) -> usize {
        match &self.storage {
            Storage::Static(s) => s.len(),
            Storage::Shared { len, .. } => *len,
        }
    }

    /// Whether the buffer is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// O(1) sub-slice.
    ///
    /// Panics if the range is reversed or exceeds this view. An empty result
    /// releases its reference to the backing allocation.
    #[inline]
    pub fn slice(&self, range: Range<usize>) -> Self {
        assert!(range.start <= range.end && range.end <= self.len());
        if range.is_empty() {
            return Self::new();
        }
        match &self.storage {
            Storage::Static(s) => Self::from_static(&s[range]),
            Storage::Shared { buf, start, .. } => Self {
                storage: Storage::Shared {
                    buf: buf.clone(),
                    start: start + range.start,
                    len: range.end - range.start,
                },
            },
        }
    }

    /// O(1) suffix. Panics if `from` exceeds the length.
    #[inline]
    pub fn slice_from(&self, from: usize) -> Self {
        self.slice(from..self.len())
    }

    /// O(1) prefix. Panics if `to` exceeds the length.
    #[inline]
    pub fn slice_to(&self, to: usize) -> Self {
        self.slice(0..to)
    }

    /// Split off the first `at` bytes, keeping the rest.
    /// Panics if `at` exceeds the length.
    #[inline]
    pub fn split_to(&mut self, at: usize) -> Self {
        let head = self.slice_to(at);
        *self = self.slice_from(at);
        head
    }

    /// Split off the tail starting at `at`, keeping the prefix.
    /// Panics if `at` exceeds the length.
    #[inline]
    pub fn split_off(&mut self, at: usize) -> Self {
        let tail = self.slice_from(at);
        *self = self.slice_to(at);
        tail
    }

    /// The underlying contiguous slice.
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        match &self.storage {
            Storage::Static(s) => s,
            Storage::Shared { buf, start, len } => &buf[*start..*start + *len],
        }
    }

    /// Copy the visible bytes into a fresh `Vec`.
    #[inline]
    pub fn to_vec(&self) -> Vec<u8> {
        self.as_slice().to_vec()
    }

    /// Return the visible bytes as a mutable vector.
    ///
    /// Reuses the allocation when this is its only owner. A sliced unique
    /// buffer moves its visible bytes to the start of that allocation.
    /// Static or still-shared buffers copy only their visible bytes.
    #[inline]
    pub fn into_vec(self) -> Vec<u8> {
        match self.storage {
            Storage::Static(s) => s.to_vec(),
            Storage::Shared { buf, start, len } => match Shared::try_unwrap(buf) {
                Ok(mut bytes) => {
                    if start != 0 {
                        bytes.copy_within(start..start + len, 0);
                    }
                    bytes.truncate(len);
                    bytes
                }
                Err(bytes) => bytes[start..start + len].to_vec(),
            },
        }
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
        if len == 0 {
            return Self::new();
        }
        Self {
            storage: Storage::Shared {
                buf: Shared::new(v),
                start: 0,
                len,
            },
        }
    }
}

impl From<Box<[u8]>> for Bytes {
    #[inline]
    fn from(b: Box<[u8]>) -> Self {
        Self::from(b.into_vec())
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
        write!(f, "Bytes(len={})", self.len())
    }
}

impl fmt::Display for Bytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match core::str::from_utf8(self.as_slice()) {
            Ok(s) => f.write_str(s),
            Err(_) => write!(f, "<invalid utf8, {} bytes>", self.len()),
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

    /// Turn into immutable [`Bytes`] without copying the payload.
    /// A nonempty buffer allocates one shared ownership header.
    #[inline]
    pub fn freeze(self) -> Bytes {
        Bytes::from(self.buf)
    }

    /// Truncate to `len`.
    #[inline]
    pub fn truncate(&mut self, len: usize) {
        self.buf.truncate(len);
    }

    /// Resize to `new_len`, filling new bytes with `value`.
    #[inline]
    pub fn resize(&mut self, new_len: usize, value: u8) {
        self.buf.resize(new_len, value);
    }

    /// Split off the tail starting at `at`.
    #[inline]
    pub fn split_off(&mut self, at: usize) -> BytesMut {
        BytesMut {
            buf: self.buf.split_off(at),
        }
    }

    /// Split off the first `at` bytes, keeping the rest.
    #[inline]
    pub fn split_to(&mut self, at: usize) -> BytesMut {
        assert!(at <= self.buf.len());
        let head = self.buf[..at].to_vec();
        self.buf.drain(..at);
        BytesMut { buf: head }
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

impl core::ops::DerefMut for BytesMut {
    #[inline]
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.buf
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_buffers_borrow_the_original_storage() {
        const DATA: &[u8] = b"static protocol bytes";
        const BUFFER: Bytes = Bytes::from_static(DATA);
        const EMPTY: Bytes = Bytes::new();
        assert!(EMPTY.is_empty());
        assert_eq!(BUFFER.as_ptr(), DATA.as_ptr());
        let view = BUFFER.slice(7..15);
        assert_eq!(view.as_ptr(), DATA[7..].as_ptr());
        assert_eq!(view.as_slice(), b"protocol");
        assert!(core::mem::size_of::<Bytes>() <= 4 * core::mem::size_of::<usize>());
    }

    #[test]
    fn freezing_and_unique_thaw_preserve_the_payload_allocation() {
        let mut original = Vec::with_capacity(4096);
        original.extend_from_slice(b"payload");
        let pointer = original.as_ptr();
        let capacity = original.capacity();
        let bytes = BytesMut::from_vec(original).freeze();
        assert_eq!(bytes.as_ptr(), pointer);
        let restored = bytes.into_vec();
        assert_eq!(restored.as_ptr(), pointer);
        assert_eq!(restored.capacity(), capacity);
        assert_eq!(restored, b"payload");
    }

    #[test]
    fn unique_sliced_thaw_reuses_storage_without_exposing_hidden_bytes() {
        let original = b"secret:visible:secret".to_vec();
        let pointer = original.as_ptr();
        let bytes = Bytes::from(original).slice(7..14);
        let mut restored = bytes.into_vec();
        assert_eq!(restored.as_ptr(), pointer);
        assert_eq!(restored, b"visible");
        restored.resize(20, 0);
        assert_eq!(&restored[7..], &[0; 13]);
    }

    #[test]
    fn shared_thaw_is_independent_and_copies_only_the_view() {
        let original = Bytes::from(b"prefix-body-suffix".to_vec());
        let view = original.slice(7..11);
        let mut restored = view.into_vec();
        assert_eq!(restored, b"body");
        restored[0] = b'B';
        assert_eq!(original.as_slice(), b"prefix-body-suffix");
    }

    #[test]
    fn every_split_and_nested_slice_preserves_bytes() {
        let input = b"0123456789";
        for bytes in [Bytes::from_static(input), Bytes::from(input.to_vec())] {
            for start in 0..=input.len() {
                for end in start..=input.len() {
                    let view = bytes.slice(start..end);
                    for split in 0..=view.len() {
                        let mut tail = view.clone();
                        let head = tail.split_to(split);
                        assert_eq!(head.as_slice(), &input[start..start + split]);
                        assert_eq!(tail.as_slice(), &input[start + split..end]);
                        let mut head = view.clone();
                        let tail = head.split_off(split);
                        assert_eq!(head.as_slice(), &input[start..start + split]);
                        assert_eq!(tail.as_slice(), &input[start + split..end]);
                    }
                }
            }
        }
    }

    #[test]
    fn empty_views_do_not_retain_large_allocations() {
        let bytes = Bytes::from(vec![1; 4096]);
        let empty = bytes.slice(5..5);
        assert!(matches!(empty.storage, Storage::Static(_)));
        let Storage::Shared { buf, .. } = &bytes.storage else {
            unreachable!()
        };
        assert_eq!(Shared::strong_count(buf), 1);
    }

    #[cfg(target_has_atomic = "ptr")]
    #[test]
    fn shared_bytes_remain_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Bytes>();
    }
}
