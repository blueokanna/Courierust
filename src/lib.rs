//! Courierust — a self-contained HTTP/1.1 + HTTP/2 + HTTP/3 + WebSocket + gRPC stack.
//!
//! The protocol core (`courierust_http`, `courierust_h1`,
//! `courierust_hpack`, `courierust_h2`, `courierust_ws`,
//! `courierust_deflate`, `courierust_quic`, `courierust_h3`,
//! `courierust_fingerprint`, `courierust_crypto`, `courierust_bytes`,
//! `courierust_io`, `courierust_error`) compiles on `no_std + alloc`
//! with **zero** third-party dependencies. The `std` feature (enabled by
//! default) adds the threaded networking layer: `courierust_pool`
//! (work-stealing scheduler), `courierust_net`, `courierust_tls` (the
//! TLS 1.2/1.3 stack), `courierust_body` (channel-backed streaming
//! bodies), `courierust_client` (the h1 pool, the h2/h3 drivers and the
//! WebSocket client), `courierust_server` (the event-driven scheduler
//! plus the WebSocket upgrade path) and `courierust_grpc`.
//!
//! Every public module carries the crate's `courierust_` prefix so no
//! module path collides with a third-party crate of the same short name
//! (e.g. `h2`, `http`, `bytes`, `grpc`, `tls`).
//!
//! Design highlights:
//!
//! * **Multi-core parallelism** — a work-stealing thread pool with
//!   per-worker LIFO caches and a global FIFO steal queue; client pools
//!   are shared per authority, and up to `max_connections_per_host` a
//!   request opens a fresh HTTP/2 connection. At that cap the pool picks
//!   the *least-loaded* connection — active streams plus in-flight
//!   request-body bytes (64 KiB units) plus a capped EWMA of per-request
//!   service time — and always prefers an idle connection for reuse
//!   regardless of its history.
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
//! TLS 1.3 (RFC 8446) and TLS 1.2 (RFC 5246 / RFC 8422) are implemented
//! from scratch under the `std` feature (`courierust_tls` module) —
//! client and server handshakes, X25519 key exchange, AES-GCM /
//! ChaCha20-Poly1305 record protection (over TLS 1.2 only the AEAD ECDHE
//! suites are offered; CBC/HMAC, static-RSA and RC4 never are), and X.509
//! chain validation — so `https://` is a first-class capability on both
//! the client and the server. The protocol core stays `no_std + alloc`
//! with zero third-party dependencies; the transport traits let the same
//! codecs also run over an externally supplied TLS stream.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![warn(missing_docs)]

#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

/// Lock a [`std::sync::Mutex`], recovering from poisoning.
///
/// A poisoned lock means some thread panicked while holding it. For a
/// server that must not escalate: the panic already failed one request,
/// and `unwrap()` would turn it into a permanent failure of every later
/// operation on the same pool, pool registry or health state — an outage
/// caused by a bug that would otherwise have cost a single request.
///
/// Recovery is sound for the structures this crate puts behind these
/// locks: each is one standard-library call away from a consistent state
/// (a map insert/remove, a queue push/pop, a counter), so there is no
/// multi-step invariant a panic could tear. Where a panic *could* leave
/// torn state, the lock is not shared in the first place.
#[cfg(feature = "std")]
#[inline]
pub(crate) fn lock<T>(m: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

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

/// The crate README, compiled as doctests by `cargo test --doc`.
///
/// Every `rust` block in `README.md` is therefore a test: a sample that
/// stops compiling fails CI instead of shipping to `docs.rs` and being
/// copied by a user. Blocks that open a socket or read a file are marked
/// `no_run`, so they are compiled and type-checked but never executed.
///
/// `README_CN.md` is not included a second time — `tests/readme_parity.rs`
/// requires the two READMEs to contain byte-identical code blocks and the
/// same layout graph, so the doctests below cover both.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
pub struct ReadmeDoctests;

/// The per-module `README.md` files, compiled as doctests by
/// `cargo test --doc` under the same contract as [`ReadmeDoctests`]: a
/// `rust` block in a module README that stops compiling fails CI.
///
/// The Chinese counterparts are covered by `tests/readme_parity.rs`,
/// which requires every `src/<module>/README.md` / `README_CN.md` pair to
/// carry the same code (comments may be translated), so a block fixed here
/// cannot drift there.
#[cfg(doctest)]
pub mod readme_doctests {
    #[doc = include_str!("courierust_bytes/README.md")]
    pub struct BytesReadme;

    #[doc = include_str!("courierust_crypto/README.md")]
    pub struct CryptoReadme;

    #[doc = include_str!("courierust_error/README.md")]
    pub struct ErrorReadme;

    #[doc = include_str!("courierust_fingerprint/README.md")]
    pub struct FingerprintReadme;

    #[doc = include_str!("courierust_io/README.md")]
    pub struct IoReadme;

    #[cfg(feature = "std")]
    #[doc = include_str!("courierust_body/README.md")]
    pub struct BodyReadme;

    #[cfg(feature = "std")]
    #[doc = include_str!("courierust_client/README.md")]
    pub struct ClientReadme;

    #[cfg(feature = "std")]
    #[doc = include_str!("courierust_grpc/README.md")]
    pub struct GrpcReadme;

    #[cfg(feature = "std")]
    #[doc = include_str!("courierust_pool/README.md")]
    pub struct PoolReadme;

    #[cfg(feature = "std")]
    #[doc = include_str!("courierust_server/README.md")]
    pub struct ServerReadme;

    #[cfg(feature = "std")]
    #[doc = include_str!("courierust_tls/README.md")]
    pub struct TlsReadme;

    /// The WebSocket README also shows the server upgrade hook and the
    /// client, so it needs `std`.
    #[cfg(feature = "std")]
    #[doc = include_str!("courierust_ws/README.md")]
    pub struct WsReadme;
}

/// The `wiki/en` pages, compiled as doctests by `cargo test --doc`.
///
/// The wiki is what a new user reads first, and it is synced to GitHub —
/// a snippet that has stopped compiling is worse than no snippet. The
/// Chinese pages are not included a second time: `tests/readme_parity.rs`
/// requires each `wiki/en/<Page>.md` to carry the same code as its
/// `wiki/zh/<页面>.md` counterpart, so these doctests cover both.
#[cfg(doctest)]
pub mod wiki_doctests {
    #[doc = include_str!("../wiki/en/Fingerprints.md")]
    pub struct Fingerprints;

    #[doc = include_str!("../wiki/en/no_std.md")]
    pub struct NoStd;

    #[cfg(feature = "std")]
    #[doc = include_str!("../wiki/en/Getting-Started.md")]
    pub struct GettingStarted;

    #[cfg(feature = "std")]
    #[doc = include_str!("../wiki/en/HTTP-Client.md")]
    pub struct HttpClient;

    #[cfg(feature = "std")]
    #[doc = include_str!("../wiki/en/HTTP-Server.md")]
    pub struct HttpServer;

    #[cfg(feature = "std")]
    #[doc = include_str!("../wiki/en/WebSockets.md")]
    pub struct WebSockets;

    #[cfg(feature = "std")]
    #[doc = include_str!("../wiki/en/gRPC.md")]
    pub struct Grpc;
}
