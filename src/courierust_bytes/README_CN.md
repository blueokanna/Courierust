# courierust_bytes

`Bytes` 持有不可变字节区间，克隆和切片的复杂度均为 O(1)。`BytesMut` 是供编码器写入的可增长缓冲区。两者支持 `no_std + alloc`，不引入外部依赖。

## 存储与所有权

- `Bytes::new` 和 `Bytes::from_static` 不分配内存；静态切片借用原始字节。
- 从非空 `Vec<u8>`、`Box<[u8]>`、`String` 转换，或调用 `BytesMut::freeze`，都会接管原有正文内存，不复制正文。共享所有权需要额外分配一个小型控制块。
- 从普通借用切片转换时会复制字节；生命周期允许时，使用 `from_static` 避免复制。
- `into_vec` 在唯一持有时复用原分配。唯一持有的子区间会原地移至缓冲区开头；共享或静态子区间只复制可见字节。
- 空切片会释放对原分配的引用。非空切片仍保留整块内存，包括原向量的备用容量；若只需长期保存大缓冲区中的一小段，可用 `to_vec` 创建紧凑副本。

支持指针宽度原子操作的目标使用 `Arc`，其他目标使用 `Rc`。后者使 `Bytes` 不具备 `Send` 和 `Sync`，编译器会拒绝不受支持的跨线程共享。`BytesMut` 在两类目标上都保持普通 `Vec` 的所有权语义。

## 用法

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
