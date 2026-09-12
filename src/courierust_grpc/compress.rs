//! gzip (RFC 1952) message compression for gRPC.
//!
//! The implementation moved to [`crate::courierust_deflate`] so the
//! **same** DEFLATE core serves gRPC's per-message gzip framing and
//! WebSocket's `permessage-deflate` extension (RFC 7692) — one audited
//! decoder instead of two. This module is kept as the gRPC-facing path
//! so existing call sites (`compress::gzip`, `compress::gunzip`, ...)
//! and downstream users keep compiling unchanged.
//!
//! gRPC uses gzip per message: each compressed message is an independent
//! gzip stream whose 5-byte framing header sets the compressed flag.

pub use crate::courierust_deflate::{
    crc32, deflate, deflate_sync, gunzip, gzip, inflate, inflate_into, Deflater, Inflater,
    MAX_WINDOW_BITS, MIN_WINDOW_BITS,
};
