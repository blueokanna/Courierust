//! QUIC v1 transport codecs (RFC 9000 / 9001 / 9002).
//!
//! This module owns the dependency-free QUIC v1 wire codecs: variable-length
//! integers, long/short packet headers, packet numbers, stream identifiers,
//! every frame type in RFC 9000 §19, and (under `std`) RFC 9001 packet
//! protection. The `courierust_h3` runtime supplies UDP I/O and the QUIC-TLS
//! adapter for the built-in HTTP/3 path.
//!
//! The runtime is intentionally explicit about its protocol boundary. The
//! long tail of the RFC 9000/9001/9002 transport is implemented and
//! exercised by the built-in runtime: PTO/time-threshold loss recovery,
//! dynamic local MAX_DATA/MAX_STREAM_DATA/MAX_STREAMS credit updates,
//! connection migration and path validation, stateless reset (generation and
//! validation), automatic bidirectional key update with the one-at-a-time
//! guard, and QPACK blocked-stream acknowledgements. Deliberately out of
//! scope: 0-RTT / early data and independent implementation interoperability
//! (which still needs dedicated evidence before broad external interop is
//! advertised). Everything in this codec is tested against the relevant RFC
//! examples and the supported runtime paths.

#![deny(unsafe_code)]

extern crate alloc;

pub mod frame;
pub mod packet;
#[cfg(feature = "std")]
pub mod protection;
pub mod stream;
pub mod varint;

/// QUIC version 1 (`0x00000001`, RFC 9000).
pub const VERSION_1: u32 = 0x0000_0001;
/// The version-negotiation packet's fixed bit: version 0 is never a real
/// version, so a packet with version `0` is a version-negotiation packet.
pub const VERSION_NEGOTIATION: u32 = 0;

/// Default QUIC packet header size (fixed bit + packet type + reserved +
/// packet number length, without the connection id and packet number).
pub const SHORT_HEADER_BIT: u8 = 0x40;
/// Long-header packet type mask.
pub const LONG_HEADER_TYPE_MASK: u8 = 0x30;
/// Long-header fixed bit.
pub const LONG_HEADER_FIXED_BIT: u8 = 0x80;

/// The maximum value encodable in a QUIC varint (2^62 - 1).
pub const VARINT_MAX: u64 = (1 << 62) - 1;
