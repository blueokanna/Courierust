//! HTTP request methods (RFC 9110 §9).

use crate::error::{Error, Result};
use crate::http::is_token;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::string::ToString;
use core::fmt;

/// An HTTP method. Well-known methods are tagged; anything else is kept
/// as an owned lowercase-preserving string.
#[derive(Clone, PartialEq, Eq, Hash)]
pub enum Method {
    /// GET
    GET,
    /// HEAD
    HEAD,
    /// POST
    POST,
    /// PUT
    PUT,
    /// DELETE
    DELETE,
    /// CONNECT
    CONNECT,
    /// OPTIONS
    OPTIONS,
    /// TRACE
    TRACE,
    /// PATCH
    PATCH,
    /// Any other registered or extension method.
    Other(Box<str>),
}

impl Method {
    /// The method as a string.
    #[inline]
    pub const fn as_str(&self) -> &str {
        match self {
            Self::GET => "GET",
            Self::HEAD => "HEAD",
            Self::POST => "POST",
            Self::PUT => "PUT",
            Self::DELETE => "DELETE",
            Self::CONNECT => "CONNECT",
            Self::OPTIONS => "OPTIONS",
            Self::TRACE => "TRACE",
            Self::PATCH => "PATCH",
            Self::Other(s) => s,
        }
    }

    /// Parse from bytes, validating the token grammar.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if !is_token(b) {
            return Err(Error::protocol("invalid method token"));
        }
        Ok(match b {
            b"GET" => Self::GET,
            b"HEAD" => Self::HEAD,
            b"POST" => Self::POST,
            b"PUT" => Self::PUT,
            b"DELETE" => Self::DELETE,
            b"CONNECT" => Self::CONNECT,
            b"OPTIONS" => Self::OPTIONS,
            b"TRACE" => Self::TRACE,
            b"PATCH" => Self::PATCH,
            _ => Self::Other(core::str::from_utf8(b)?.into()),
        })
    }

    /// Whether the method is defined as safe (RFC 9110 §9.2.1).
    #[inline]
    pub fn is_safe(&self) -> bool {
        matches!(
            self,
            Self::GET | Self::HEAD | Self::OPTIONS | Self::TRACE
        )
    }

    /// Whether the method is idempotent (RFC 9110 §9.2.2).
    #[inline]
    pub fn is_idempotent(&self) -> bool {
        self.is_safe()
            || matches!(
                self,
                Self::PUT | Self::DELETE | Self::Other(_) if self.as_str() == "PROPFIND"
            )
            || matches!(self, Self::PUT | Self::DELETE)
    }
}

impl Default for Method {
    #[inline]
    fn default() -> Self {
        Self::GET
    }
}

impl fmt::Display for Method {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Debug for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Method({})", self.as_str())
    }
}

impl PartialEq<str> for Method {
    #[inline]
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl PartialEq<&str> for Method {
    #[inline]
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

impl From<&'static str> for Method {
    fn from(s: &'static str) -> Self {
        Method::from_bytes(s.as_bytes()).unwrap_or_else(|_| Self::Other(s.into()))
    }
}

impl From<String> for Method {
    fn from(s: String) -> Self {
        Method::from_bytes(s.as_bytes()).unwrap_or_else(|_| Self::Other(s.into_boxed_str()))
    }
}

impl core::str::FromStr for Method {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::from_bytes(s.as_bytes())
    }
}

impl From<Method> for String {
    fn from(m: Method) -> Self {
        m.as_str().to_string()
    }
}
