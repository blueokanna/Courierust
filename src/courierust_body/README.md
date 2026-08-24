# courierust_body

The std-layer message body: `Empty`, `Bytes`, and **`Channel`** — a streaming body backed by an mpsc channel.

## What `Channel` buys you

A handler doesn't have to build the whole response before returning. With `Body::Channel`, you hand back a receiver and push chunks from another thread — SSE-style pushes, streaming file reads, long-poll feeds. The server drains the channel and frames the chunks (chunked for h1, DATA frames for h2, bytes for h3).

On the client side, the same type carries response bodies that arrive over time.

## The backpressure story

The h2 server path is flow-control-aware: channel bodies are **only drained when the connection accepts more data**. A slow reader doesn't cause an unbounded buffer — the server stops draining the channel until the peer's flow-control window opens up again. That's the difference between "streaming" and "buffering forever".

## Usage

```rust
use courierust::courierust_body::Body;
use courierust::courierust_bytes::Bytes;
use std::sync::mpsc::channel;

let (tx, rx) = channel::<Result<Bytes>>();
// hand `rx` to the response, push from anywhere:
tx.send(Ok(Bytes::from_static(b"chunk 1")));
```

The `Result<Bytes>` payload is deliberate: a producer can signal an error mid-stream, and the consumer sees it as an error, not a truncated body.
