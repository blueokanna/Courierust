//! HKDF (RFC 5869) and the TLS 1.3 labeled expansion (RFC 8446 §7.1).
//!
//! Implemented in [`super::hmac`]; this module re-exports the public
//! surface so the crypto layout matches the documentation.

pub use super::hmac::{expand, expand_label, extract};
