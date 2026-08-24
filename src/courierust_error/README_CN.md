# courierust_error

整个栈共用一个错误类型。`ErrorKind`（廉价 `Copy` 判别式）+ 可选的、给人看的信息。`no_std`、零依赖。

## 为什么只用一个类型

每一层——h1、h2、h3、HPACK、TLS、客户端、服务端、gRPC——都会失败。如果每层自己发明一个错误类型，你就会得到 `From` impl 爆炸和每个边界上的"这到底是哪个错误？"猜谜。一个类型 = 一个 match，判别式告诉你类别，哪怕 message 帮不上忙。

## 这些类别

刻意粗糙——重点是机器可判，不是精确：

- `Io`、`UnexpectedEof`、`WouldBlock`——传输层。
- `Protocol`、`InvalidHeader`、`Overflow`——"你发来的是垃圾"（或者撞了上限）。
- `Timeout`——超时。
- `H2(u32)`、`Grpc(u32)`——线上错误码原样穿透，HTTP/2 错误码和 gRPC status 在向上传的过程中不丢。
- `Canceled`——任一方重置/中止。
- `Other`——应用层。

协议层用 message 细化粗糙的类别（`Error::protocol("invalid chunk size")`），所以你两个都有：能分支的类别 + 能记日志的细节。

## 用法

```rust
use courierust::courierust_error::{Error, ErrorKind, Result};

match err.kind {
    ErrorKind::WouldBlock => /* 还没就绪，再试 */,
    ErrorKind::Protocol => /* 对端违反了 RFC */,
    ErrorKind::H2(code) => /* HTTP/2 错误码原样保留 */,
    _ => /* 记 err.message */,
}
```
