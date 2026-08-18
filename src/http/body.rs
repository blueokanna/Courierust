//! Message bodies for the `no_std` core.
//!
//! The threaded layer (`std` feature) extends this with streaming bodies
//! via a channel-backed variant defined in the `client`/`server` modules.

use crate::bytes::Bytes;
use alloc::string::String;
use alloc::vec::Vec;

/// A fully materialized body: empty or a byte buffer.
#[derive(Clone, Default, PartialEq, Eq, Hash)]
pub enum Body {
    /// No body.
    #[default]
    Empty,
    /// A complete body in memory.
    Bytes(Bytes),
}

impl Body {
    #[inline]
    pub fn is_empty(&self) -> bool {
        match self {
            Self::Empty => true,
            Self::Bytes(b) => b.is_empty(),
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        match self {
            Self::Empty => 0,
            Self::Bytes(b) => b.len(),
        }
    }

    /// Extract the bytes if fully materialized.
    #[inline]
    pub fn into_bytes(self) -> Option<Bytes> {
        match self {
            Self::Empty => None,
            Self::Bytes(b) => Some(b),
        }
    }

    /// Borrow as bytes.
    #[inline]
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Empty => None,
            Self::Bytes(b) => Some(b.as_slice()),
        }
    }
}

impl From<Bytes> for Body {
    #[inline]
    fn from(b: Bytes) -> Self {
        if b.is_empty() {
            Self::Empty
        } else {
            Self::Bytes(b)
        }
    }
}

impl From<Vec<u8>> for Body {
    #[inline]
    fn from(v: Vec<u8>) -> Self {
        Self::from(Bytes::from(v))
    }
}

impl From<&'static [u8]> for Body {
    #[inline]
    fn from(b: &'static [u8]) -> Self {
        Self::from(Bytes::from_static(b))
    }
}

impl From<&'static str> for Body {
    #[inline]
    fn from(s: &'static str) -> Self {
        Self::from(Bytes::from_static(s.as_bytes()))
    }
}

impl From<String> for Body {
    #[inline]
    fn from(s: String) -> Self {
        Self::from(Bytes::from(s))
    }
}

impl core::fmt::Debug for Body {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Empty => write!(f, "Body::Empty"),
            Self::Bytes(b) => write!(f, "Body::Bytes({} bytes)", b.len()),
        }
    }
}
