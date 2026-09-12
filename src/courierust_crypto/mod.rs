//! Self-contained, `no_std` digests used by the fingerprint layer
//! (MD5 for JA3, SHA-256 for JA4), the WebSocket handshake (SHA-1,
//! required by RFC 6455 §4.2.2) and the base64 codec both use for their
//! wire tokens. Implementations follow the public specifications
//! (RFC 1321, FIPS 180-4, RFC 3174, RFC 4648 §4) and contain no unsafe
//! code.

pub mod base64;
pub mod md5;
pub mod sha1;
pub mod sha256;
