//! Self-contained, `no_std` digests used by the fingerprint layer
//! (MD5 for JA3, SHA-256 for JA4). Implementations follow the public
//! specifications (RFC 1321, FIPS 180-4) and contain no unsafe code.

pub mod md5;
pub mod sha256;
