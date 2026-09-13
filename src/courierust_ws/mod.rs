//! WebSocket (RFC 6455) with `permessage-deflate` (RFC 7692), zero
//! third-party dependencies. A `no_std + alloc` protocol core
//! ([`frame`], [`utf8`], [`handshake`], [`session`]) plus thin `std`
//! adapters in [`crate::courierust_server`] and
//! [`crate::courierust_client`].
//!
//! What is unusual here:
//!
//! * Servers write payloads straight from the caller's buffer; clients
//!   mask in 16 KiB windows. Frame headers are parsed out of the read
//!   buffer without copying.
//! * [`session::Session::poll_message`] never blocks and never drops
//!   partial state, so one state machine drives both a blocking worker
//!   and an event-loop reactor.
//! * Non-minimal length encodings, reserved bits without a negotiated
//!   extension, unknown opcodes, fragmented or oversized control frames,
//!   duplicate `Sec-WebSocket-Key`/`Version` headers and a wrong masking
//!   direction are rejected before a byte is buffered for the
//!   application.
//! * Text is validated incrementally, so a character split across frames
//!   is accepted and an illegal sequence is rejected at the byte that
//!   makes it illegal (after inflating, for `permessage-deflate`).
//! * `max_frame`, `max_message`, `max_fragments`, a ≤32 KiB
//!   decompression window and a cap on the inflated size bound every
//!   per-connection cost.
//! * [`handshake::OriginPolicy`] compares `Origin` with the request's own
//!   origin, believing `X-Forwarded-*` only from a peer inside a
//!   configured [`handshake::IpNet`].
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
    accept_key, client_ip, effective_host, is_secure, is_token, is_valid_key, is_websocket_upgrade,
    origin_equivalent, origin_matches, parse_extension_value, parse_extensions, CompressionParams,
    ExtensionOffer, HandshakeRejection, IpNet, OriginPolicy, PerMessageDeflate, PmDeflatePolicy,
    WsOffer, PERMESSAGE_DEFLATE, WS_VERSION,
};
pub use session::{Event, MaskSource, Role, Session, SessionConfig, Stats};
pub use utf8::Utf8Validator;
pub use writer::{CloseFlag, FrameWriter, VecSink};
