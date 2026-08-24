# courierust_io

两个极小的 trait——`Read` 和 `Write`——外加 `BufReader`、`BufWriter` 和一个 `Scratch` 行/头缓冲区。这是**让整个协议核心保持 `no_std` 的接缝**。

## 想法

协议层（h1、h2、h3、hpack）只知道 `Read` 和 `Write`。它们不知道 socket 是什么、TLS 是什么、甚至不知道 `std` 是什么。任何实现这两个 trait 的传输——TCP 流、TLS 流、内存管道、测试 harness——都能驱动整套 codec 栈。让核心保持零依赖的全部戏法就在这里：**codec 与传输无关，因为 trait 足够小。**

## 为什么 trait 刻意做小

`std::io::Read`/`Write` 拖进 `std` 和一整套组合子词汇。这两个 trait 是：

- `read(&mut self, buf) -> Result<usize>`——字节源，干净 EOF 返回 `Ok(0)`；
- `write(&mut self, buf) -> Result<usize>` + `flush()`——字节汇。

就这些。小到适配任何传输只需几行，`no_std` 到核心永远见不到 `std`。

## 还有什么

- `BufReader`——带精确读取和大小端整数辅助的缓冲读（h1/h2 codec 需要这些）。
- `BufWriter`——缓冲写。
- `Scratch`——可复用行缓冲区，让稳态 HTTP/1.1 keep-alive 请求**零按请求分配**。

`&mut T` 的 blanket impl 意味着你可以在任何需要 `Read` 的地方传 `&mut stream`，生命周期保持清醒。

## 用法

```rust
use courierust::courierust_io::{Read, Write};

// 你的传输只需实现这两个 trait。
impl Read for MyPipe { /* ... */ }
impl Write for MyPipe { /* ... */ }

// 然后栈里任何 codec 都能在它上面跑，原样不动。
```
