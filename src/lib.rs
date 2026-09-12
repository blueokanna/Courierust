//! Courierust — a self-contained HTTP/1.1 + HTTP/2 + HTTP/3 + WebSocket + gRPC stack.
//!
//! The protocol core (`courierust_http`, `courierust_hpack`,
//! `courierust_h2`, `courierust_ws`, `courierust_deflate`,
//! `courierust_quic`, `courierust_h3`, `courierust_fingerprint`,
//! `courierust_crypto`, `courierust_bytes`, `courierust_io`) compiles on
//! `no_std + alloc` with **zero** third-party dependencies. The `std`
//! feature (enabled by default) adds the threaded networking layer:
//! `courierust_pool` (work-stealing scheduler), `courierust_net`,
//! `courierust_client` (the h1 pool, the h2/h3 drivers and the WebSocket
//! client), `courierust_server` (the event-driven scheduler plus the
//! WebSocket upgrade path) and `courierust_grpc`.
//!
//! Every public module carries the crate's `courierust_` prefix so no
//! module path collides with a third-party crate of the same short name
//! (e.g. `h2`, `http`, `bytes`, `grpc`, `tls`).
//!
//! Design highlights:
//!
//! * **Multi-core parallelism** — a work-stealing thread pool with
//!   per-worker LIFO caches and a global FIFO steal queue; client pools are
//!   shared per authority, and HTTP/2 requests are assigned to the least
//!   reserved accepting driver up to `max_connections_per_host`.
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
//! * **WebSocket** — RFC 6455 framing, masking, UTF-8 validation, the
//!   close handshake and RFC 7692 `permessage-deflate`, in
//!   `courierust_ws`. Masking is XORed in 16-byte lanes (a 4-byte
//!   repeating key cannot vectorise, but 16 is a multiple of four, so
//!   every lane starts at the same key phase), a payload over 8 KiB is
//!   read straight into the message buffer instead of through the
//!   buffered reader, and the DEFLATE context is reused per message
//!   rather than rebuilt. A live HTTP/1.1 connection is upgraded in
//!   place by both server drivers — in the event reactor an idle
//!   WebSocket costs a poller slot, not a thread — and the client speaks
//!   `ws://` / `wss://` over the crate's own TLS stack.
//! * **HTTP/3 over QUIC v1** — `courierust_quic` (packet and frame
//!   codecs, varints, header protection, key update) plus `courierust_h3`
//!   (QPACK, H3 framing, and a poller-driven UDP reactor whose poll
//!   timeout is an absolute protocol deadline rather than a fixed tick).
//! * **Fingerprint profiles** — exact Chrome HTTP/2 settings/header
//!   ordering plus JA3/JA4 TLS `ClientHello` parameter profiles with
//!   self-contained MD5/SHA-256, so a browser-shaped fingerprint can be
//!   fed to an external TLS layer of your choice.
//!
//! TLS 1.3 (RFC 8446) is implemented from scratch under the `std`
//! feature (`courierust_tls` module) — client and server handshakes,
//! X.25519 key exchange, AES-GCM / ChaCha20-Poly1305 record protection,
//! and X.509 chain validation — so `https://` is a first-class
//! capability on both the client and the server. The protocol core stays
//! `no_std + alloc` with zero third-party dependencies; the transport
//! traits let the same codecs also run over an externally supplied TLS
//! stream.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![warn(missing_docs)]

#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod courierust_bytes;
pub mod courierust_crypto;
pub mod courierust_deflate;
pub mod courierust_error;
pub mod courierust_fingerprint;
pub mod courierust_h1;
pub mod courierust_h2;
pub mod courierust_h3;
pub mod courierust_hpack;
pub mod courierust_http;
pub mod courierust_io;
pub mod courierust_quic;
#[cfg(feature = "std")]
pub mod courierust_tls;
pub mod courierust_ws;

#[cfg(feature = "std")]
pub mod courierust_body;
#[cfg(feature = "std")]
pub mod courierust_client;
#[cfg(feature = "std")]
pub mod courierust_grpc;
#[cfg(feature = "std")]
pub mod courierust_net;
#[cfg(feature = "std")]
pub mod courierust_pool;
#[cfg(feature = "std")]
pub mod courierust_server;

pub use courierust_bytes::Bytes;
pub use courierust_error::{Error, ErrorKind, Result};
