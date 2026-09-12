//! WebSocket (RFC 6455) with `permessage-deflate` (RFC 7692), written
//! from the specification with zero third-party dependencies.
//!
//! The module is split the same way the rest of the crate is: a
//! `no_std + alloc` protocol core ([`frame`], [`utf8`], [`handshake`],
//! [`session`]) that any transport can drive, and thin `std` adapters in
//! [`crate::courierust_server`] and [`crate::courierust_client`] that
//! place it on TCP/TLS sockets.
//!
//! # What this implementation does differently
//!
//! * **Zero-copy reads, fused copy-unmask writes.** Frame headers are
//!   parsed directly out of the connection's read buffer; payload bytes
//!   are unmasked while they are copied into the message buffer (one
//!   pass, not two) using 64-bit lanes whose four phase words are
//!   precomputed once per frame. Servers write payloads straight from
//!   the caller's buffer (no copy at all, since server frames are
//!   unmasked); clients mask in fixed 16 KiB windows so a gigabyte-scale
//!   message costs a 16 KiB scratch buffer.
//! * **An interruptible session.** [`session::Session::poll_message`]
//!   never blocks and never drops partial state, so the *same* state
//!   machine drives a blocking worker thread and an event-loop reactor.
//!   Idle connections on the reactor cost a buffer, not a thread.
//! * **Strictness that matches a proxy's.** Non-minimal length
//!   encodings, reserved bits without a negotiated extension, unknown
//!   opcodes, fragmented or oversized control frames, duplicate
//!   `Sec-WebSocket-Key`/`Version` headers and any frame with the wrong
//!   masking direction are all rejected before a byte is buffered for
//!   the application. Two hops can therefore never disagree about where
//!   a frame ends — the property that turns framing bugs into request
//!   smuggling.
//! * **Incremental UTF-8 validation.** Text is validated as it streams
//!   through, with an eight-bytes-per-iteration ASCII fast path and a
//!   12-state machine for multi-byte sequences, so a character split
//!   across fragments is accepted and an illegal sequence is rejected at
//!   the byte that makes it illegal (`permessage-deflate` moves the
//!   check after inflating, where it has to be).
//! * **Bounded everything.** `max_frame`, `max_message`,
//!   `max_fragments`, a ≤32 KiB decompression window, and a
//!   decompression-bomb cap on the *inflated* size. A peer chooses none
//!   of these numbers.
//! * **Proxy-aware origin policy.** Because browsers do not apply the
//!   same-origin policy to WebSocket connects, `Origin` is the only
//!   CSRF defence an endpoint has. [`handshake::OriginPolicy`] compares
//!   it against the request's own origin, using `X-Forwarded-*` headers
//!   *only* when the peer address is inside a configured
//!   [`handshake::IpNet`] — the arrangement a TLS-terminating Nginx or
//!   Traefik deployment needs.
//!
//! ```no_run
//! # #[cfg(feature = "std")]
//! # fn main() -> courierust::Result<()> {
//! use courierust::courierust_ws::{FrameWriter, MaskSource, Session, SessionConfig, VecSink};
//! use courierust::courierust_io::{BufReader, SliceReader};
//!
//! // A session over any transport the crate already speaks. A client
//! // would use `MaskSource::Random`; a server never masks.
//! let reader = BufReader::new(SliceReader::new(&[]), 4096);
//! let writer = FrameWriter::new(VecSink::new(), MaskSource::None, None);
//! let mut session = Session::new(reader, writer, SessionConfig::default());
//! session.send_text("hello")?;
//! session.flush()?;
//! # Ok(())
//! # }
//! # #[cfg(not(feature = "std"))]
//! # fn main() {}
//! ```

pub mod frame;
pub mod handshake;
pub mod session;
pub mod utf8;
pub mod writer;

pub use frame::{
    close, FrameHeader, FrameSink, Mask, OpCode, StreamSink, MASK_WINDOW, MASK_WINDOW_MAX,
    MAX_CONTROL_PAYLOAD, MAX_HEADER_LEN,
};
pub use handshake::{
    accept_key, client_ip, effective_host, is_secure, is_valid_key, is_websocket_upgrade,
    origin_equivalent, origin_matches, parse_extensions, CompressionParams, ExtensionOffer,
    HandshakeRejection, IpNet, OriginPolicy, PerMessageDeflate, PmDeflatePolicy, WsOffer,
    WS_VERSION,
};
pub use session::{Event, MaskSource, Role, Session, SessionConfig, Stats};
pub use utf8::Utf8Validator;
pub use writer::{CloseFlag, FrameWriter, VecSink};
