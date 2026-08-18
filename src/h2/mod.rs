//! HTTP/2 (RFC 9113): frames, stream state machine, flow control and
//! RFC 9218 extensible priorities.
//!
//! This module is `no_std`-capable; the framing/state-machine core is
//! generic over [`crate::io::Read`]/[`crate::io::Write`] so the same
//! codec runs over TCP or a TLS stream.

pub mod connection;
pub mod error;
pub mod flow;
pub mod frame;
pub mod priority;
pub mod settings;
pub mod stream;
