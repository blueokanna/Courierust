//! HTTP/3 (RFC 9114) — framing, stream roles, settings, and QPACK
//! (RFC 9204) field-line compression.
//!
//! This is the HTTP layer that runs on top of QUIC:
//!
//! * [`frame`] — HTTP/3 frame types, SETTINGS identifiers, and the
//!   unidirectional stream roles (control / push / QPACK encoder /
//!   QPACK decoder).
//! * [`qpack`] — the complete QPACK codec: the 99-entry static table,
//!   prefix integers, Huffman strings, every field-line representation,
//!   the dynamic table, and the encoder/decoder instruction streams.
//!
//! Under `std`, [`runtime`] wires these codecs to the built-in QUIC v1
//! packet-protection/TLS adapter and a UDP reactor. That path is bounded and
//! usable for the implemented HTTP/3 request/response subset: TLS 1.3 with
//! ALPN `h3`, control/QPACK streams, request streams, response trailers,
//! GOAWAY validation, retransmission, and strict stream reassembly.
//!
//! It is not a blanket claim of full RFC 9000/9001/9114 deployment readiness,
//! but the transport long tail is implemented and exercised: PTO/time-threshold
//! loss recovery, dynamic local flow-control credit (MAX_DATA / MAX_STREAM_DATA
//! / MAX_STREAMS), connection migration and path validation, stateless reset
//! (generation and validation), automatic bidirectional key update with the
//! one-at-a-time guard, and QPACK blocked-stream acknowledgements (Section
//! Acknowledgment / Stream Cancellation / Insert Count Increment on the decoder
//! stream). Deliberately out of scope: 0-RTT / early data (replay protection is
//! not taken on) and independent implementation interoperability, which must be
//! demonstrated before advertising broad external interop.

#![deny(unsafe_code)]

extern crate alloc;

pub mod frame;
pub mod qpack;
#[cfg(feature = "std")]
mod qpack_conn;
#[cfg(feature = "std")]
pub mod runtime;

pub use frame::Frame;
pub use qpack::DynamicTable;
