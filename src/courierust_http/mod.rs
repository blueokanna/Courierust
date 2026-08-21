//! HTTP message model: methods, status, versions, headers, URIs, bodies.

pub mod body;
pub mod header;
pub mod method;
pub mod request;
pub mod response;
pub mod status;
pub mod uri;
pub mod version;

pub use body::Body;
pub use header::{HeaderMap, HeaderName, HeaderValue};
pub use method::Method;
pub use request::Request;
pub use response::Response;
pub use status::StatusCode;
pub use uri::PathAndQuery;
pub use version::Version;

/// Validates that a byte sequence is a valid HTTP token (RFC 9110 §5.6.2).
pub(crate) fn is_token(b: &[u8]) -> bool {
    !b.is_empty()
        && b.iter()
            .all(|&c| c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&c))
}
