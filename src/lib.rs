//! Courierust — a self-contained HTTP/1.1 + HTTP/2 + gRPC stack.
//!
//! The protocol core (`http`, `hpack`, `h2`, `fingerprint`, `crypto`,
//! `bytes`, `io`) compiles on `no_std + alloc` with **zero** third-party
//! dependencies. The `std` feature (enabled by default) adds the threaded
//! networking layer: `pool` (work-stealing scheduler), `net`, `client`,
//! `server` and `grpc`.
//!
//! Design highlights:
//!
//! * **Multi-core parallelism** — a work-stealing thread pool with
//!   per-worker LIFO caches and a global FIFO steal queue; client
//!   connection pools are sharded per worker and HTTP/2 connections are
//!   distributed across workers, so throughput scales with core count.
//! * **RFC 9218 client priority frames** (`PRIORITY_UPDATE`, frame type
//!   `0x10`) with a Weighted-Urgency Calendar Scheduler (WUCS): eight
//!   urgency buckets combined with Deficit Round Robin anti-starvation
//!   and round-robin interleaving for incremental streams — O(1)
//!   scheduling decision.
//! * **Batched Credit Reflow (BCR)** flow control — received data is
//!   acknowledged in batches rather than one `WINDOW_UPDATE` per frame,
//!   cutting control-frame overhead.
//! * **Table-driven HPACK** — 8-bit two-level Huffman decode tables and a
//!   hash-accelerated static/dynamic header index fast path.
//! * **Fingerprint profiles** — exact Chrome HTTP/2 settings/header
//!   ordering plus JA3/JA4 TLS `ClientHello` parameter profiles with
//!   self-contained MD5/SHA-256, so a browser-shaped fingerprint can be
//!   fed to an external TLS layer of your choice.
//!
//! TLS 1.3 (RFC 8446) is implemented from scratch under the `std`
//! feature (`tls` module) — client and server handshakes, X.25519 key
//! exchange, AES-GCM / ChaCha20-Poly1305 record protection, and X.509
//! chain validation — so `https://` is a first-class capability on both
//! the client and the server. The protocol core (`http`, `hpack`, `h2`,
//! `fingerprint`, `crypto`, `bytes`, `io`) stays `no_std + alloc` with
//! zero third-party dependencies; the transport traits let the same
//! codecs also run over an externally supplied TLS stream.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![warn(missing_docs)]

#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod bytes;
pub mod crypto;
pub mod error;
pub mod fingerprint;
pub mod h2;
pub mod hpack;
pub mod http;
pub mod io;
#[cfg(feature = "std")]
pub mod tls;

#[cfg(feature = "std")]
pub mod body;
#[cfg(feature = "std")]
pub mod client;
#[cfg(feature = "std")]
pub mod grpc;
#[cfg(feature = "std")]
pub mod h1;
#[cfg(feature = "std")]
pub mod net;
#[cfg(feature = "std")]
pub mod pool;
#[cfg(feature = "std")]
pub mod server;

pub use bytes::Bytes;
pub use error::{Error, ErrorKind, Result};
