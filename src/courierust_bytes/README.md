# courierust_bytes

`Bytes` owns an immutable byte range with O(1) cloning and slicing. `BytesMut` is the growable encoder buffer. Both support `no_std + alloc` without external dependencies.

## Storage and ownership

- `Bytes::new` and `Bytes::from_static` do not allocate. Static views borrow the original bytes.
- Converting a nonempty `Vec<u8>`, `Box<[u8]>`, or `String`, and calling `BytesMut::freeze`, transfer the payload allocation without copying it. Shared ownership adds one small allocation.
- Converting a borrowed slice copies its bytes. Use `from_static` when its lifetime permits borrowing.
- `into_vec` reuses uniquely owned storage. A unique subrange is moved to the front in place; shared or static subranges copy only their visible bytes.
- Empty slices release their ownership of the original allocation. Nonempty slices retain it, including spare vector capacity. Use `to_vec` to avoid retaining a large buffer for a small view.

Targets with pointer-width atomics use `Arc`; other targets use `Rc`. The latter makes `Bytes` neither `Send` nor `Sync`, so unsupported cross-thread sharing is rejected by the compiler. `BytesMut` retains ordinary `Vec` ownership on either target.

## Usage

```rust
use courierust::courierust_bytes::{Bytes, BytesMut};

# fn main() {
let b = Bytes::from_static(b"hello world");
let tail = b.slice_from(6);       // O(1), no copy
let clone = tail.clone();        // static view, no allocation

let mut m = BytesMut::new();
m.extend_from_slice(b"hello");
let done: Bytes = m.freeze();    // preserves the payload allocation
# let _ = (clone, done);
# }
```
