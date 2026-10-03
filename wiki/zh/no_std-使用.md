# no_std 使用

协议核心在 `no_std + alloc` 下编译，**零依赖**。这是完整的线上协议栈：HTTP 消息模型、HPACK、HTTP/2 编解码/状态机/流控、WUCS 优先级调度、指纹、自带的 MD5/SHA-256。适合嵌入式固件、内核模块等没有标准库的环境。

## 哪些模块不依赖 std

| 模块 | 内容 |
|---|---|
| `courierust_http` | 请求/响应/方法/状态码/头/URI |
| `courierust_h1` | HTTP/1.x 线格式编解码：请求/状态行、头、chunked 分帧 |
| `courierust_hpack` | 编码器/解码器、Huffman、静态+动态表 |
| `courierust_h2` | 帧、SETTINGS、流、流控、WUCS、`PRIORITY_UPDATE` |
| `courierust_fingerprint` | JA3 / JA4 / Chrome HTTP/2 profile |
| `courierust_crypto` | MD5、SHA-256 |
| `courierust_bytes` / `courierust_io` | 字节缓冲、Read/Write trait |
| `courierust_error` | 统一错误类型 |

需要 `std`（在默认 feature 后面）的：`courierust_pool`、`courierust_net`、`courierust_tls`、`courierust_body`、`courierust_client`、`courierust_server`、`courierust_grpc`。

## 开启方式

```toml
[dependencies]
courierust = { version = "1.0.8", default-features = false }
```

构建检查：

```bash
cargo build --no-default-features --lib
```

需要分配器（全局 allocator + `alloc`）。crate 自带的 `io::Read`/`io::Write` trait 取代 `std::io`——用你平台上的字节管道驱动它们。

## 不用 std 驱动编解码

一个最简 HTTP/2 客户端会话，一帧一帧地推进：

```rust,no_run
use courierust::courierust_h2::connection::{Config, Connection};
use courierust::courierust_h2::priority::Priority;
use courierust::courierust_hpack::HeaderList;

# fn main() -> courierust::Result<()> {
// 为你的传输层实现 crate::courierust_io::Read / crate::courierust_io::Write。
struct MyTransport; // ... Read + Write 实现 ...
# impl courierust::courierust_io::Read for MyTransport {
#     fn read(&mut self, _buf: &mut [u8]) -> courierust::Result<usize> { Ok(0) }
# }
# impl courierust::courierust_io::Write for MyTransport {
#     fn write(&mut self, buf: &[u8]) -> courierust::Result<usize> { Ok(buf.len()) }
#     fn flush(&mut self) -> courierust::Result<()> { Ok(()) }
# }

let mut conn = Connection::new(MyTransport, MyTransport, Config {
    client: true,
    ..Default::default()
});

// 开一个请求流，排队头+体，然后 poll() 推进。
# let my_header_block: HeaderList = Default::default();
# let payload = courierust::courierust_bytes::Bytes::from_static(b"payload");
let sid = conn.open_request(Priority::default())?;
conn.send_headers(sid, &my_header_block, false)?;
conn.send_data(sid, payload, true)?;

loop {
    let progressed = conn.poll()?; // 有帧被写出/读入则为 true
    while let Some(ev) = conn.next_event() {
#         let _ = ev;
        // Event::Headers / Event::Data / Event::StreamClosed / ...
    }
    if !progressed {
        // 当前没有更多工作——让出给事件循环
        break;
    }
}
# Ok(())
# }
```

`Connection` 对 `crate::courierust_io::Read`/`Write` 泛型化，同样的代码既能驱动 TCP、TLS，也能驱动 UART 式字节流。

## 无 std 的哈希

```rust
use courierust::courierust_crypto::md5::md5_hex;
use courierust::courierust_crypto::sha256::sha256_hex;

# fn main() {
let h = md5_hex(b"hello");    // "5d41402abc4b2a76b9719d911017c592"
# assert_eq!(h, "5d41402abc4b2a76b9719d911017c592");
let h = sha256_hex(b"hello"); // "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
# assert_eq!(h, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
# }
```

这两个是 crate 里仅有的加密实现（给 JA3/JA4 用），都是小而查表驱动、零依赖。
