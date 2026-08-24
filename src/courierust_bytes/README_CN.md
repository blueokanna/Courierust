# courierust_bytes

`Bytes`——不可变、`Arc` 背靠背的字节切片，**O(1) 切片、廉价克隆**。`BytesMut`——编码器用的可增长构建器。`no_std`、零依赖。

## 这是什么

如果你认识 `bytes` crate，你就认识这个——同样的想法，手写一份，让栈保持零依赖。`Bytes` 是帧载荷和头值的通货：切出子区间 O(1)（不拷贝），克隆是引用计数 +1（不拷贝），底层分配安全共享。

`BytesMut` 是编码器往里写的东西——一个可增长缓冲区，能交出 `Bytes` 视图。

## 为什么在这里重要

一个 `no_std` 零依赖的栈，不能伸手去 crates.io 拿 `bytes`。但你仍然需要它的性质，因为每一层都在把字节区间递给下一层：h2 帧的载荷、HPACK literal 的值、chunked body 的一段。替代方案——到处拷贝——是"网络栈很慢却说不出为什么"的标准成因。

## 用法

```rust
use courierust::courierust_bytes::{Bytes, BytesMut};

let b = Bytes::from_static(b"hello world");
let tail = b.slice(6..);          // O(1)，不拷贝
let clone = tail.clone();         // 引用计数 +1，不拷贝

let mut m = BytesMut::new();
m.extend_from_slice(b"hello");
let done: Bytes = m.freeze();
```
