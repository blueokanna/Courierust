# Examples

Every example in the repository compiles and runs as-is (`cargo run --example <name>`). They are the fastest way to see the stack in action.

| Example | What it shows | Run |
|---|---|---|
| `hello` | Minimal client + server over h2c in one file | `cargo run --example hello` |
| `greeter` | gRPC server + client: unary (raw + typed), error status | `cargo run --example greeter` |
| `streaming` | Server streams a `Body::Channel`, client consumes chunk by chunk | `cargo run --example streaming` |
| `priority` | RFC 9218: high-urgency stream scheduled ahead of a low-urgency backlog | `cargo run --example priority` |
| `redirects` | 302 chains followed automatically (RFC 9110) | `cargo run --example redirects` |
| `fingerprint` | Print the JA3 / JA4 / Chrome HTTP/2 fingerprint values | `cargo run --example fingerprint` |
| `https` | HTTPS (TLS 1.2 + 1.3) end to end: self-signed Ed25519 identity, validating client, h2 + HTTP/1.1 over ALPN | `cargo run --example https` |
| `h3` | HTTP/3 (QUIC v1 + TLS 1.3) end to end: cold connect, pooled reuse, flow control, concurrent streams, certificate rejection | `cargo run --example h3` |
| `ws_echo` | WebSocket echo server **and** client in one process: upgrade, text/binary round trips, server push on the same connection, subprotocol, clean close | `cargo run --example ws_echo` |
| `ws_client` | WebSocket client with the production options: subprotocols, Origin, compression preference, read deadline, bounded close | `cargo run --example ws_client` |
| `grpc_streaming` | gRPC server/client/bidi streaming, deadlines, gzip negotiation, metadata + interceptors | `cargo run --example grpc_streaming` |
| `grpc_health` | `grpc.health.v1.Health` `Check` and `Watch`, with the protobuf hand-encoded | `cargo run --example grpc_health` |
| `grpc_framing` | The 5-byte length-prefixed gRPC message frame, in isolation | `cargo run --example grpc_framing` |
| `grpc_compression` | The from-scratch gzip / DEFLATE / CRC-32 codec behind `grpc-encoding: gzip` | `cargo run --example grpc_compression` |
| `protocol_core` | HPACK + h2 codec over an in-memory pipe (no sockets), plus the self-contained hashes | `cargo run --example protocol_core` |
| `huffman` | HPACK Huffman (RFC 7541 §5.2) with the table-driven decoder | `cargo run --example huffman` |
| `h1_codec` | HTTP/1.1 wire codec primitives, no sockets involved | `cargo run --example h1_codec` |
| `h3_frames` | The HTTP/3 frame layer (RFC 9114 §7.2) in isolation | `cargo run --example h3_frames` |
| `qpack` | The QPACK codec (RFC 9204): static table, prefix integers, Huffman, blocked streams | `cargo run --example qpack` |
| `quic_varint` | QUIC variable-length integers (RFC 9000 §16) | `cargo run --example quic_varint` |
| `quic_protection` | QUIC v1 packet protection (RFC 9001 §5): Initial keys, AEAD sealing, header protection | `cargo run --example quic_protection` |
| `pool` | The work-stealing thread pool in isolation | `cargo run --example pool` |
| `bytes` | Zero-copy `Bytes` windows and `BytesMut` append buffers | `cargo run --example bytes` |
| `crypto` | The self-contained MD5 / SHA-256 that feed the fingerprints | `cargo run --example crypto` |
| `diag` | Loopback h2 echo used for diagnostics | `cargo run --example diag` |

## hello

One file: spin up a server on an ephemeral port, then GET and POST to it with an HTTP/2 client. The starting point for everything else.

## greeter

A background gRPC server with two methods plus a client that calls them — raw-bytes `call`, typed `call_unary`, and an error path that surfaces `grpc-status` on the client.

## streaming

The server returns a `Body::Channel`; a producer thread feeds it; the client drains the channel receiver incrementally. Works over HTTP/1.1 (chunked) and HTTP/2.

## priority

Fires 32 `urgency=7` requests, then one `urgency=0` request. The WUCS scheduler must not let the low-urgency backlog starve the high-urgency stream — the example prints how fast the high-urgency request completes.

## redirects

A two-hop `302 -> 302 -> 200` chain; the client follows it transparently and you see the final response.

## fingerprint

Prints the exact ClientHello parameters (`chrome_tls_profile`) plus the JA3 string/hash, JA4, and the Chrome HTTP/2 SETTINGS order — the values you feed to your own TLS layer.

## https

A server with a self-signed Ed25519 identity (the DER files under `tests/certs/`) and a client that trusts that same certificate as its root. The server speaks both h2 (ALPN) and HTTP/1.1 over TLS; the client GETs and POSTs `https://` URLs and prints status + body. Swap in your own certificate chain + key for real deployments.

## protocol_core

The `no_std`-capable core with no sockets: HPACK encode/decode round trip, an h2 `Connection` driven over an in-memory pipe (any type implementing `io::Read`/`io::Write` works), and the dependency-free MD5/SHA-256.

## diag

Loopback h2 echo with status + body printed — handy for confirming the stack works before pointing it at a real endpoint.

## h3

A QUIC server and the pooled H3 client over the same self-signed identity as `https`: the first request pays the QUIC handshake + TLS 1.3 + Retry address validation, every later request rides a fresh stream on the same connection, then large-response flow control, concurrent multiplexing and a certificate rejection are demonstrated.

## ws_echo

The complete WebSocket round trip in one file: the server hook accepts `/echo`, the client upgrades, exchanges a text and a binary message, asks the server for a push on the same connection (the cross-thread `WsSender` path), prints the negotiated subprotocol and the negotiated `permessage-deflate` parameters, then closes cleanly — the client's `on_close` and the server's `on_close` both run.

## ws_client

The client half on its own, pointed at any endpoint (`ws://` or `wss://`, including a public echo server): subprotocol offers, an `Origin` header, a compression preference, a read deadline, and a bounded close handshake — the options that matter in production, printed so you can see what the peer agreed to.

## grpc_streaming

The call shapes `greeter` does not cover: server-streaming, client-streaming and bidi, plus a `grpc-timeout` deadline that surfaces as `DEADLINE_EXCEEDED`, gzip compression negotiated through `grpc-encoding`, request metadata and an interceptor.

## grpc_health

`grpc.health.v1.Health` served without protobuf codegen: the two tiny protobuf messages are hand-encoded, and both `Check` (unary) and `Watch` (server-streaming) run on the crate's own HTTP/2 + gRPC framing.

## grpc_framing

The 5-byte prefix every gRPC message wears — one flag byte (`0` identity, `1` gzip) plus a big-endian length — framed and re-framed in isolation, including the over-limit rejection.

## grpc_compression

The from-scratch RFC 1951/1952 encoder and decoder that back `grpc-encoding: gzip`, exercised on a highly compressible payload and on a decompression bomb whose inflated size must be refused rather than allocated.

## huffman

The RFC 7541 §5.2 code with the two-level table-driven decoder: encode, decode, and the checks that make a hostile Huffman block (padding, EOS, truncation) fail instead of looping.

## h1_codec

The request/status-line and header parsing primitives with no sockets involved, including the message-boundary strictness (trailing junk rejected) that keeps this server and a proxy from disagreeing about where a request ends.

## h3_frames

HTTP/3 framing (RFC 9114 §7.2) on its own: varint-addressed `type` + `length` + payload, with unknown extension frames preserved instead of rejected.

## qpack

The QPACK codec (RFC 9204) in isolation: the 99-entry static table, prefix integers, Huffman literals, and the blocked-stream arithmetic an HTTP/3 peer relies on.

## quic_varint

QUIC's self-describing integers (RFC 9000 §16): the top two bits pick a 1 / 2 / 4 / 8-byte encoding, so a small value costs one byte on the wire.

## quic_protection

QUIC v1 packet protection (RFC 9001 §5): Initial keys derived from the connection ID (HKDF → AES-128-GCM), payload AEAD-sealed with the packet number as nonce and the header as AAD, and header protection masking the length field.

## pool

The work-stealing scheduler under every server and client connection: per-worker LIFO caches, a global FIFO steal queue, nested job submission, and the idle-longest preference.

## bytes

Zero-copy `Bytes` windows: `slice`, `split_to`, `split_off` and `freeze` move a (start, len) window over one allocation instead of copying, which is what makes the codec paths allocation-free.

## crypto

The dependency-free MD5 (RFC 1321) and SHA-256 (FIPS 180-4) that also feed JA3/JA4 — with the published test vectors printed as they are checked.
