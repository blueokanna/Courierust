//! Header names, values and an order-preserving header map.
//!
//! Order preservation matters for HTTP/2 (header blocks are order
//! sensitive) and for browser-fingerprint-accurate emission.

use crate::courierust_bytes::Bytes;
use crate::courierust_error::{Error, Result};
use crate::courierust_http::is_token;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

/// Case-insensitive ASCII equality for header names (RFC 9110 §5.1).
#[inline]
pub(crate) fn eq_ignore_ascii_case(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b.iter())
            .all(|(x, y)| x.eq_ignore_ascii_case(y))
}

/// An HTTP header field name. Invariant: a lowercase token (RFC 9110
/// tchar set), so equality is a plain byte comparison.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HeaderName(Box<str>);

impl HeaderName {
    /// Parse and validate from bytes; lowercases on success.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if !is_token(b) {
            return Err(Error::invalid_header_name());
        }
        let mut lower = Vec::with_capacity(b.len());
        for &c in b {
            lower.push(c.to_ascii_lowercase());
        }
        // Safety of the invariant: we just lowercased and validated tokens.
        Ok(Self(
            String::from_utf8(lower)
                .map_err(|_| Error::invalid_header_name())?
                .into_boxed_str(),
        ))
    }

    /// A static header name, validated at construction.
    #[inline]
    pub fn from_static(s: &'static str) -> Self {
        Self::from_bytes(s.as_bytes()).expect("invalid static header name")
    }

    /// Parse a header name as it appears in an HPACK block: HTTP/2
    /// pseudo-headers (`:name`) are allowed as a leading colon followed
    /// by a token, and regular names must be lowercase tokens.
    pub fn from_hpack_bytes(b: &[u8]) -> Result<Self> {
        if b.first() == Some(&b':') {
            let rest = &b[1..];
            if rest.is_empty() || !is_token(rest) || rest.iter().any(|c| c.is_ascii_uppercase()) {
                return Err(Error::invalid_header_name());
            }
            return Ok(Self(core::str::from_utf8(b)?.into()));
        }
        Self::from_bytes(b)
    }

    /// A known lowercase header name (no validation). Allows a leading
    /// `:` for HTTP/2 pseudo-headers.
    #[inline]
    pub fn from_lowercase(s: &'static str) -> Self {
        debug_assert!({
            let b = s.as_bytes();
            let rest = if b.first() == Some(&b':') { &b[1..] } else { b };
            !rest.is_empty()
                && rest
                    .iter()
                    .all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"-_.~".contains(&c))
        });
        Self(s.into())
    }

    /// The name as a string slice.
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The name as bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Whether this is an HTTP/2 pseudo-header (`:name`).
    #[inline]
    pub fn is_pseudo(&self) -> bool {
        self.0.starts_with(':')
    }
}

impl fmt::Display for HeaderName {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for HeaderName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HeaderName({})", self.0)
    }
}

impl core::str::FromStr for HeaderName {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::from_bytes(s.as_bytes())
    }
}

impl From<&'static str> for HeaderName {
    fn from(s: &'static str) -> Self {
        Self::from_bytes(s.as_bytes())
            .unwrap_or_else(|_| panic!("invalid static header name: {s:?}"))
    }
}

impl From<HeaderName> for String {
    fn from(n: HeaderName) -> Self {
        n.0.into()
    }
}

/// An HTTP header field value: visible ASCII or obs-text (RFC 9110
/// §5.5). No CR, LF or NUL is permitted.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HeaderValue(Bytes);

impl HeaderValue {
    /// Validate and wrap bytes.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.iter()
            .any(|&c| c == 0 || c == b'\r' || c == b'\n' || (c < 0x20 && c != b'\t'))
        {
            return Err(Error::invalid_header_value());
        }
        Ok(Self(Bytes::from(b)))
    }

    /// Wrap a static value (assumed valid).
    #[inline]
    pub fn from_static(s: &'static str) -> Self {
        Self(Bytes::from_static(s.as_bytes()))
    }

    /// The value as bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// The value as a UTF-8 string if valid.
    #[inline]
    pub fn to_str(&self) -> Result<&str> {
        Ok(core::str::from_utf8(self.0.as_slice())?)
    }

    /// Whether the value is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Length in bytes.
    #[inline]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// The underlying buffer.
    #[inline]
    pub fn into_bytes(self) -> Bytes {
        self.0
    }
}

impl fmt::Display for HeaderValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match core::str::from_utf8(self.0.as_slice()) {
            Ok(s) => f.write_str(s),
            Err(_) => write!(f, "<binary {} bytes>", self.0.len()),
        }
    }
}

impl fmt::Debug for HeaderValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HeaderValue({:?})", self.to_str().unwrap_or("<binary>"))
    }
}

impl From<Bytes> for HeaderValue {
    fn from(b: Bytes) -> Self {
        Self(b)
    }
}

impl From<Vec<u8>> for HeaderValue {
    fn from(v: Vec<u8>) -> Self {
        Self(Bytes::from(v))
    }
}

impl From<String> for HeaderValue {
    fn from(s: String) -> Self {
        Self(Bytes::from(s))
    }
}

impl From<&str> for HeaderValue {
    fn from(s: &str) -> Self {
        Self(Bytes::from(s))
    }
}

/// An order-preserving multimap of header fields.
///
/// `insert` replaces all fields with the same name (HTTP semantics);
/// `append` adds a duplicate. Iteration is in insertion order, which the
/// HTTP/2 and fingerprint layers depend on.
#[derive(Clone, Default)]
pub struct HeaderMap {
    entries: Vec<(HeaderName, HeaderValue)>,
}

impl HeaderMap {
    /// Empty map.
    #[inline]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Empty map with capacity.
    #[inline]
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            entries: Vec::with_capacity(cap),
        }
    }

    /// Replace all fields named `name` with a single `value`
    /// (case-insensitive). Returns the value of the last removed field.
    pub fn insert(&mut self, name: HeaderName, value: HeaderValue) -> Option<HeaderValue> {
        let mut removed = None;
        let mut i = 0;
        while i < self.entries.len() {
            if eq_ignore_ascii_case(self.entries[i].0.as_bytes(), name.as_bytes()) {
                removed = Some(self.entries.remove(i).1);
            } else {
                i += 1;
            }
        }
        self.entries.push((name, value));
        removed
    }

    /// Append a field, keeping any existing fields with the same name.
    pub fn append(&mut self, name: HeaderName, value: HeaderValue) {
        self.entries.push((name, value));
    }

    /// Insert a pseudo-header, which MUST precede regular fields.
    pub fn insert_pseudo(&mut self, name: HeaderName, value: HeaderValue) {
        debug_assert!(name.is_pseudo());
        let pos = self
            .entries
            .iter()
            .position(|(n, _)| !n.is_pseudo())
            .unwrap_or(self.entries.len());
        self.entries.insert(pos, (name, value));
    }

    /// First value for `name` (case-insensitive).
    pub fn get(&self, name: &str) -> Option<&HeaderValue> {
        self.entries
            .iter()
            .find(|(n, _)| eq_ignore_ascii_case(n.as_bytes(), name.as_bytes()))
            .map(|(_, v)| v)
    }

    /// All values for `name` (case-insensitive).
    pub fn get_all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a HeaderValue> + 'a {
        self.entries
            .iter()
            .filter(move |(n, _)| eq_ignore_ascii_case(n.as_bytes(), name.as_bytes()))
            .map(|(_, v)| v)
    }

    /// Whether `name` is present.
    pub fn contains_key(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    /// Remove all fields named `name`; returns the first removed value.
    pub fn remove(&mut self, name: &str) -> Option<HeaderValue> {
        let mut removed = None;
        let mut i = 0;
        while i < self.entries.len() {
            if eq_ignore_ascii_case(self.entries[i].0.as_bytes(), name.as_bytes()) {
                let (_, v) = self.entries.remove(i);
                if removed.is_none() {
                    removed = Some(v);
                }
            } else {
                i += 1;
            }
        }
        removed
    }

    /// Number of stored fields (including duplicates).
    #[inline]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Clear all fields.
    #[inline]
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Iterate in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = (&HeaderName, &HeaderValue)> {
        self.entries.iter().map(|(n, v)| (n, v))
    }

    /// Mutable iterate in insertion order.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&HeaderName, &mut HeaderValue)> {
        self.entries.iter_mut().map(|(n, v)| (&*n, v))
    }

    /// Iterate over values only.
    pub fn values(&self) -> impl Iterator<Item = &HeaderValue> {
        self.entries.iter().map(|(_, v)| v)
    }

    /// Collect distinct header names.
    pub fn names(&self) -> Vec<&HeaderName> {
        let mut out: Vec<&HeaderName> = Vec::new();
        for (n, _) in &self.entries {
            if !out.iter().any(|x| x.as_bytes() == n.as_bytes()) {
                out.push(n);
            }
        }
        out
    }

    /// Convert into a vector of owned pairs.
    #[inline]
    pub fn into_vec(self) -> Vec<(HeaderName, HeaderValue)> {
        self.entries
    }

    /// Borrow the underlying pairs.
    #[inline]
    pub fn as_vec(&self) -> &[(HeaderName, HeaderValue)] {
        &self.entries
    }
}

impl fmt::Debug for HeaderMap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(
                self.entries
                    .iter()
                    .map(|(n, v)| (n.as_str(), v.to_str().unwrap_or("<binary>"))),
            )
            .finish()
    }
}

impl Extend<(HeaderName, HeaderValue)> for HeaderMap {
    fn extend<T: IntoIterator<Item = (HeaderName, HeaderValue)>>(&mut self, iter: T) {
        self.entries.extend(iter);
    }
}

impl From<Vec<(HeaderName, HeaderValue)>> for HeaderMap {
    fn from(v: Vec<(HeaderName, HeaderValue)>) -> Self {
        Self { entries: v }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_name_lowercases_and_validates() {
        assert_eq!(
            HeaderName::from_bytes(b"Content-Type").unwrap().as_str(),
            "content-type"
        );
        assert!(HeaderName::from_bytes(b"bad name").is_err());
        assert!(HeaderName::from_bytes(b"").is_err());
    }

    #[test]
    fn header_value_rejects_crlf() {
        assert!(HeaderValue::from_bytes(b"ok value").is_ok());
        assert!(HeaderValue::from_bytes(b"bad\r\nvalue").is_err());
        assert!(HeaderValue::from_bytes(b"bad\x00value").is_err());
    }

    #[test]
    fn map_insert_replace_and_append() {
        let mut m = HeaderMap::new();
        m.append(
            HeaderName::from_static("set-cookie"),
            HeaderValue::from_static("a=1"),
        );
        m.append(
            HeaderName::from_static("set-cookie"),
            HeaderValue::from_static("b=2"),
        );
        assert_eq!(m.get_all("set-cookie").count(), 2);
        m.insert(
            HeaderName::from_static("SET-COOKIE"),
            HeaderValue::from_static("c=3"),
        );
        assert_eq!(m.get_all("set-cookie").count(), 1);
        assert_eq!(m.get("set-cookie").unwrap().to_str().unwrap(), "c=3");
    }
}
