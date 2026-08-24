# courierust_h2

HTTP/2 (RFC 9113): frames, stream state machine, flow control, and RFC 9218 priorities. `no_std`, zero dependencies, generic over the crate's `Read`/`Write` traits — so the *same codec* runs over TCP or over a TLS stream.

Yes, another HTTP/2 implementation. No, this one doesn't wrap `h2`.

## What's here

- **Complete frame codec** — DATA / HEADERS / PRIORITY / RST_STREAM / SETTINGS / PUSH_PROMISE / PING / GOAWAY / WINDOW_UPDATE / CONTINUATION, plus the RFC 9218 `PRIORITY_UPDATE` (type `0x10`).
- **Stream state machine** following §5.1 strictly. An illegal transition ends in `PROTOCOL_ERROR`. No "close enough" states.
- **Two-level flow control** (connection + per-stream), windows advanced per frame, checked against overflow on both directions.
- **RFC 9218 priorities** — `Priority` header / `PRIORITY_UPDATE` parsing, backed by the WUCS scheduler (`priority.rs`). It's O(1) per frame and provably anti-starvation; the design write-up is in `blogs/01-wucs-scheduler.md`.
- **BCR (Batched Credit Reflow)** — received-data credit is returned in batches instead of one `WINDOW_UPDATE` per frame. Control frames drop by an order of magnitude; the window never collapses to zero so the sender never stalls on RTT. See `blogs/02-bcr-flow-control.md`.

## Architecture

`connection.rs` is the stateful heart — it owns the stream table, both flow-control windows, the WUCS scheduler, and the encoder/decoder wiring, and it emits an ordered event stream the transport layer consumes. The rest are the pieces:

| file | role |
|---|---|
| `frame.rs` | wire codec for every frame type |
| `stream.rs` | per-stream state + send/recv windows |
| `flow.rs` | the `FlowWindow` with saturating i64 arithmetic |
| `settings.rs` | SETTINGS tracking and the RFC-mandated reconfiguration rules |
| `priority.rs` | RFC 9218 parsing + the WUCS scheduler |
| `error.rs` | HTTP/2 error codes → the crate's unified `Error` |

The connection is generic over `Read`/`Write`, which is what lets the blocking server, the h2 client driver thread, and (through the TLS record layer) HTTPS all reuse one implementation.

## The hardening

This layer treats every peer byte as hostile: HPACK bombs (integer overflow, header-list cap, dynamic-table size, Huffman EOS/padding), flow-control window overflow (`FLOW_CONTROL_ERROR`), DATA on bodyless messages, `content-length` mismatch at stream end, RST on idle streams, `SETTINGS_TIMEOUT`, and keepalive dead-peer detection. There are 30 hardening tests for exactly this.

## Usage

You usually don't touch this directly — `courierust_client` and `courierust_server` drive it. But if you want a raw h2 codec over your own transport, `connection::Connection` is public and well-tested.
