# courierust_grpc

gRPC without the dependency tree. gRPC is HTTP/2 + length-prefixed binary messages + `grpc-status` metadata — implemented here on top of the crate's own client and server. No tonic, no prost, no tower.

## What's here

- **All four call shapes** — unary, server-streaming, client-streaming, bidi, on both client and server.
- **Deadlines** — `grpc-timeout` is sent by the client and enforced server-side (malformed → `INVALID_ARGUMENT`, expired → `DEADLINE_EXCEEDED`).
- **Metadata & interceptors** — arbitrary metadata plus a client-side `Interceptor` hook.
- **Load balancing** — `dns:///` targets round-robin over resolved addresses.
- **Health** — `grpc.health.v1.Health` with `Check` (unary) and `Watch` (server-streaming); no reflection.
- **Compression** — `gzip` and `identity` message compression with full negotiation (gRPC A6). The gzip codec is **implemented from scratch** (`compress`): decompression handles any standard producer's DEFLATE (stored/fixed/dynamic), and the decompressed size is bounded by `max_message_size` on both ends, so a compressed bomb can't bypass the size limit.

## The batteries-included part

- **`proto`** — a from-scratch protobuf wire codec (varints, fixed widths, length-delimited, packed repeated fields, ZigZag, bounded nesting). Zero third-party crates.
- **`generated`** — build-time codegen: `build.rs` compiles every `proto/*.proto` into type-safe, IDE-friendly Rust structs + wire codecs + typed gRPC client stubs. The canonical `proto/helloworld.proto` ships as `generated::helloworld`; drop in your own `.proto` files and they're generated automatically.

If you already have a protobuf ecosystem, you're not locked in — `EncodeMessage` / `DecodeMessage` are the seam. Implement them for your types (or wrap prost), and everything else just works.

## Honest scope

No reflection service (needs a protobuf schema registry — external responsibility). No interceptors on the server side. The 4 MiB default per-message ceiling is a hard cap — set `max_message_size` explicitly for larger payloads.

## Usage

```rust
use courierust::courierust_grpc::{GrpcClient, GrpcServer};

// Server: implement Service, or just pass a closure
let server = GrpcServer::bind("127.0.0.1:50051", |method: &str, req: Bytes| {
    Ok(Bytes::from(format!("echo({method}): {}", String::from_utf8_lossy(&req))))
})?;
let _h = server.serve_background()?;

// Client
let client = GrpcClient::new("http://127.0.0.1:50051")?;
let reply = client.call("helloworld.Greeter/SayHello", Bytes::from("world"))?;
```

`examples/grpc_streaming.rs` demos all four call shapes, deadlines, gzip negotiation, metadata and interceptors; `examples/grpc_health.rs` demos `Check` + `Watch`.
