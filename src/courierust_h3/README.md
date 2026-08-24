# courierust_h3

HTTP/3 (RFC 9114): framing, stream roles, SETTINGS, and QPACK (RFC 9204) field-line compression. The codecs are `no_std`; under `std`, a UDP reactor + QUIC-TLS adapter runs the HTTP/3 path end to end against the built-in QUIC v1 codecs and TLS 1.3.

## What's here

- **`frame.rs`** — HTTP/3 frame types, SETTINGS identifiers, and the unidirectional stream roles (control / push / QPACK encoder / QPACK decoder).
- **`qpack.rs`** — the complete QPACK codec: the **99-entry static table**, prefix integers, Huffman strings, every field-line representation (T bit, relative/post-base indexing), the dynamic table, and the encoder/decoder instruction streams. Validated against RFC 9204 Appendix B.1–B.4.
- **`runtime.rs`** (std) — the UDP reactor wiring it all together: QUIC v1 packet protection, TLS 1.3 with ALPN `h3`, control/QPACK streams, request streams, response trailers, GOAWAY validation, retransmission, and strict stream reassembly.

## The QPACK gotcha

QPACK's static table is **0-indexed**, unlike HPACK's 1-indexed table. Get this wrong and every indexed field line decodes to the wrong header. It's exactly the kind of off-by-one that passes smoke tests and fails in production — the appendix vectors exist to catch it.

## Honest boundary

The transport long tail is implemented and exercised: PTO/time-threshold loss recovery, dynamic local flow-control credit (MAX_DATA / MAX_STREAM_DATA / MAX_STREAMS), connection migration and path validation, stateless reset (generation and validation), automatic bidirectional key update with the one-at-a-time guard, and QPACK blocked-stream acknowledgements (Section Acknowledgment / Stream Cancellation / Insert Count Increment). What remains deliberately out of scope: 0-RTT / early data (replay protection is not taken on), and independent-implementation interop — the quinn+h3 handshake interop gap is reported honestly in the benchmark suite rather than faked. Those two are the remaining items before treating the H3 path as Internet-ready.

## Usage

The public `Client`/`Server` (`courierust_client` / `courierust_server`) route `http3://` (and `https://` with ALPN `h3`) into this runtime. `examples/h3.rs` is a working end-to-end demo: cold vs pooled connections, large-response flow control, concurrent multiplexing, and cert rejection.
