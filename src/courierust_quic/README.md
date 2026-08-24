# courierust_quic

QUIC v1 wire codecs (RFC 9000 / 9001 / 9002): variable-length integers, long/short packet headers, packet numbers, stream identifiers, every frame type in RFC 9000 §19, and (under `std`) RFC 9001 packet protection. `no_std` capable, zero dependencies.

## What's here

- **Varints** — the `2^N`-length prefix integers of RFC 9000 §16, tested against the appendix examples.
- **Packet headers** — long and short forms, packet-number recovery per Appendix A.2.
- **Stream identifiers** — type/index decoding, client/server and bidirectional/unidirectional.
- **All frame types** from §19, including ECN ACK (`0x03`) and DATAGRAM.
- **Packet protection** (`protection.rs`, std) — the RFC 9001 §5–6 AEAD + header-protection primitives: TLS 1.3 key schedule via HKDF-Expand-Label (`tls13 quic key` / `quic iv` / `quic hp`), the v1 Initial salt, Retry integrity tag, and per-packet-number nonce construction. The header-protection mask uses the full cipher block, not the truncated sample.

## The design call

`protection.rs` deliberately owns **only** packet protection. Packet-number spaces, loss recovery, and stream scheduling live in the runtime above it. Keeping the AEAD code independent means it can be tested against RFC vectors without opening a socket — the wire primitive is verified in isolation before the transport ever touches it.

## Honest boundary

The transport long tail is implemented and exercised: PTO/time-threshold loss recovery, dynamic local `MAX_DATA`/`MAX_STREAM_DATA`/`MAX_STREAMS` credit, connection migration and path validation, stateless reset (generation and validation), automatic bidirectional key update with the one-at-a-time guard, and QPACK blocked-stream acknowledgements. Deliberately out of scope: 0-RTT / early data, and independent-implementation interoperability. Those two are the remaining items before advertising broad external interop.

## Usage

You probably don't use this directly either — `courierust_h3`'s runtime drives it over a UDP reactor. But if you're building your own QUIC transport, the codecs here are the part you can trust and test in isolation.
