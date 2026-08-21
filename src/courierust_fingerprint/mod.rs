//! Browser fingerprint profiles: exact Chrome HTTP/2 behavior plus
//! JA3/JA4 TLS `ClientHello` parameter sets.
//!
//! TLS itself is intentionally external (this crate has zero
//! dependencies); the profiles here produce the exact cipher suite,
//! extension, ALPN and HTTP/2 settings data a browser-shaped client
//! presents, ready to feed into your own TLS layer.

pub mod h2;
pub mod ja3;
pub mod ja4;
pub mod profile;

pub use h2::ChromeH2Fingerprint;
pub use ja3::{ja3, ja3_hash, ja3_string};
pub use ja4::ja4;
pub use profile::{chrome_tls_profile, TlsProfile};
