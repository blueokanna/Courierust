# courierust_bytes

`Bytes` — an immutable, `Arc`-backed byte slice with **O(1) slicing and cheap clone**. `BytesMut` — the growable builder used by encoders. `no_std`, zero dependencies.

## What it is

If you know the `bytes` crate, you know this — it's the same idea, written by hand so the stack stays dependency-free. `Bytes` is the currency of frame payloads and header values: slicing off a sub-range is O(1) (no copy), cloning is a refcount bump (no copy), and the underlying allocation is shared safely.

`BytesMut` is what encoders write into — a growable buffer that hands out `Bytes` views.

## Why it matters here

In a stack that's `no_std` and zero-dependency, you can't reach for `bytes` on crates.io. But you still need its properties, because every layer hands byte ranges to the next one: an h2 frame's payload, an HPACK literal's value, a chunked body segment. The alternative — copying everywhere — is how you end up with a networking stack that's slow and can't explain why.

## Usage

```rust
use courierust::courierust_bytes::{Bytes, BytesMut};

let b = Bytes::from_static(b"hello world");
let tail = b.slice(6..);          // O(1), no copy
let clone = tail.clone();         // refcount bump, no copy

let mut m = BytesMut::new();
m.extend_from_slice(b"hello");
let done: Bytes = m.freeze();
```
