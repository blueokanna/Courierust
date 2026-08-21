//! Self-contained cryptographic primitives for TLS 1.3 (RFC 8446).
//!
//! Everything here is implemented from the public specifications with
//! no unsafe code and no third-party crates:
//!
//! * [`chacha20`] / [`poly1305`] / [`chacha20poly1305`] — RFC 8439 AEAD
//! * [`aes`] / [`gcm`] — AES block cipher and GCM mode (RFC 5288 / FIPS
//!   197) for the AES-GCM TLS 1.3 suites
//! * [`hash`] — incremental SHA-256 / SHA-384
//! * [`hmac`] / [`hkdf`] — RFC 2104 / RFC 5869 + RFC 8446 label expansion
//! * [`x25519`] — RFC 7748 ECDH
//! * [`rsa`] — RSA signature verification (PKCS#1 v1.5 and PSS)
//! * [`ed25519`] — RFC 8032 signature verification
//! * [`ecdsa`] — ECDSA P-256 verification (FIPS 186-4 / SEC 1)
//! * [`rng`] — OS-seeded ChaCha20 DRBG
//!
//! All comparison/selection operations on secret data are constant-time;
//! secret-dependent branches and indexing are avoided.

pub mod chacha20;
pub mod chacha20poly1305;
pub mod hash;
pub mod hkdf;
pub mod hmac;
pub mod poly1305;
pub mod rng;
pub mod x25519;

#[cfg(feature = "std")]
pub mod aes;
#[cfg(feature = "std")]
pub mod ecdsa;
#[cfg(feature = "std")]
pub mod ed25519;
#[cfg(feature = "std")]
pub mod gcm;
#[cfg(feature = "std")]
pub mod rsa;

pub use chacha20poly1305::constant_time_eq;
