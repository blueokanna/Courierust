//! Unified error type shared by every layer of the stack.
//!
//! Kept dependency-free and `no_std`-compatible: the optional message is a
//! heap string, the kind is a cheap `Copy` discriminant.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::string::ToString;
use core::fmt;

/// Coarse error category. Protocol layers refine it with a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorKind {
    /// Underlying transport (socket) failure.
    Io,
    /// The peer closed the connection before the message was complete.
    UnexpectedEof,
    /// A protocol violation (HTTP/1, HTTP/2, HPACK, gRPC).
    Protocol,
    /// Malformed header name or value.
    InvalidHeader,
    /// A value exceeded an implementation limit (frame size, table size,
    /// send-buffer watermark, header-list cap, ...).
    Overflow,
    /// The operation exceeded its deadline.
    Timeout,
    /// The transport reported that no data is currently available
    /// (non-blocking mode).
    WouldBlock,
    /// HTTP/2 error code (RFC 9113 §7). Payload in `message`.
    H2(u32),
    /// gRPC status code. Payload in `message`.
    Grpc(u32),
    /// The stream/connection was reset or canceled by either side.
    Canceled,
    /// Application-level failure.
    Other,
}

/// Error with a kind and an optional human-readable detail.
#[derive(Debug, Clone)]
pub struct Error {
    /// Machine-checkable category.
    pub kind: ErrorKind,
    /// Optional detail string.
    pub message: Option<Box<str>>,
}

/// Convenience alias for `Result<T, Error>`.
pub type Result<T, E = Error> = core::result::Result<T, E>;

impl Error {
    /// Build an error from a kind.
    #[inline]
    pub fn new(kind: ErrorKind) -> Self {
        Self {
            kind,
            message: None,
        }
    }

    /// Build an error with a message.
    #[inline]
    pub fn with_message(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: Some(message.into().into_boxed_str()),
        }
    }

    /// Generic I/O failure.
    #[inline]
    pub fn io(msg: impl Into<String>) -> Self {
        Self::with_message(ErrorKind::Io, msg)
    }

    /// The operation exceeded its deadline.
    #[inline]
    pub fn timeout(msg: impl Into<String>) -> Self {
        Self::with_message(ErrorKind::Timeout, msg)
    }

    /// Unexpected end of stream.
    #[inline]
    pub fn eof() -> Self {
        Self::new(ErrorKind::UnexpectedEof)
    }

    /// Protocol violation.
    #[inline]
    pub fn protocol(msg: impl Into<String>) -> Self {
        Self::with_message(ErrorKind::Protocol, msg)
    }

    /// A limit was exceeded.
    #[inline]
    pub fn overflow(msg: impl Into<String>) -> Self {
        Self::with_message(ErrorKind::Overflow, msg)
    }

    /// The peer reset or canceled the operation.
    #[inline]
    pub fn canceled(msg: impl Into<String>) -> Self {
        Self::with_message(ErrorKind::Canceled, msg)
    }

    /// HTTP/2 error code wrapper.
    #[inline]
    pub fn h2(code: u32, msg: impl Into<String>) -> Self {
        Self::with_message(ErrorKind::H2(code), msg)
    }

    /// gRPC status wrapper.
    #[inline]
    pub fn grpc(code: u32, msg: impl Into<String>) -> Self {
        Self::with_message(ErrorKind::Grpc(code), msg)
    }

    /// Malformed header name.
    #[inline]
    pub fn invalid_header_name() -> Self {
        Self::with_message(ErrorKind::InvalidHeader, "invalid header name")
    }

    /// Malformed header value.
    #[inline]
    pub fn invalid_header_value() -> Self {
        Self::with_message(ErrorKind::InvalidHeader, "invalid header value")
    }

    /// Returns the HTTP/2 error code if this error carries one.
    #[inline]
    pub fn h2_code(&self) -> Option<u32> {
        match self.kind {
            ErrorKind::H2(c) => Some(c),
            _ => None,
        }
    }

    /// Returns the gRPC status code if this error carries one.
    #[inline]
    pub fn grpc_code(&self) -> Option<u32> {
        match self.kind {
            ErrorKind::Grpc(c) => Some(c),
            _ => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            ErrorKind::H2(c) => write!(f, "HTTP/2 error 0x{c:x}")?,
            ErrorKind::Grpc(c) => write!(f, "gRPC status {c}")?,
            k => write!(f, "{k:?}")?,
        }
        if let Some(m) = &self.message {
            write!(f, ": {m}")?;
        }
        Ok(())
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

impl From<core::str::Utf8Error> for Error {
    fn from(e: core::str::Utf8Error) -> Self {
        Self::with_message(ErrorKind::InvalidHeader, e.to_string())
    }
}

impl From<core::fmt::Error> for Error {
    fn from(_: core::fmt::Error) -> Self {
        Self::new(ErrorKind::Other)
    }
}

#[cfg(feature = "std")]
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        use std::io::ErrorKind as K;
        let kind = match e.kind() {
            K::UnexpectedEof => ErrorKind::UnexpectedEof,
            K::TimedOut => ErrorKind::Timeout,
            K::ConnectionReset | K::ConnectionAborted | K::BrokenPipe => ErrorKind::Canceled,
            _ => ErrorKind::Io,
        };
        Self::with_message(kind, e.to_string())
    }
}

#[cfg(feature = "std")]
impl From<Error> for std::io::Error {
    fn from(e: Error) -> Self {
        std::io::Error::other(e)
    }
}
