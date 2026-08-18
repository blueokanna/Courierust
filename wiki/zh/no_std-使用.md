# no_std 使用

协议核心在 `no_std + alloc` 下编译，**零依赖**。这是完整的线上协议栈：HTTP 消息模型、HPACK、HTTP/2 编解码/状态机/流控、WUCS 优先级调度、指纹、自带的 MD5/SHA-256。适合嵌入式固件、内核模块等没有标准库的环境。

## 哪些模块不依赖 std

| 模块 | 内容 |
|---|---|
| `http` | 请求/响应/方法/状态码/头/URI |
| `hpack` | 编码器/解码器、Huffman、静态+动态表 |
| `h2` | 帧、SETTINGS、流、流控、WUCS、`PRIORITY_UPDATE` |
| `fingerprint` | JA3 / JA4 / Chrome HTTP/2 profile |
| `crypto` | MD5、SHA-256 |
| `bytes` / `io` | 字节缓冲、Read/Write trait |
| `error` | 统一错误类型 |

需要 `std`（在默认 feature 后面）的：`pool`、`net`、`body`、`client`、`server`、`h1`、`grpc`。

## 开启方式

```toml
[dependencies]
courierust = { version = "0.1", default-features = false }
```

构建检查：

```bash
cargo build --no-default-features --lib
```

需要分配器（全局 allocator + `alloc`）。crate 自带的 `io::Read`/`io::Write` trait 取代 `std::io`——用你平台上的字节管道驱动它们。

## 不用 std 驱动编解码

一个最简 HTTP/2 客户端会话，一帧一帧地推进：

```rust
use courierust::bytes::BytesMut;
use courierust::h2::connection::{Config, Connection};
use courierust::h2::priority::Priority;
use courierust::io::{BufReader, BufWriter};

// 为你的传输层实现 crate::io::Read / crate::io::Write。
struct MyTransport; // ... Read + Write 实现 ...

let reader = BufReader::new(MyTransport, 4096);
let writer = BufWriter::new(MyTransport, 4096);
let mut conn = Connection::new(reader, writer, Config {
    client: true,
    ..Default::default()
});

// 开一个请求流，排队头+体，然后 poll() 推进。
let sid = conn.open_request(Priority::default())?;
conn.send_headers(sid, &my_header_block, false)?;
conn.send_data(sid, payload, true)?;

loop {
    let progressed = conn.poll()?; // 有帧被写出/读入则为 true
    while let Some(ev) = conn.next_event() {
        // Event::Headers / Event::Data / Event::StreamClosed / ...
    }
    if !progressed {
        // 当前没有更多工作——让出给事件循环
        break;
    }
}
```

`Connection` 对 `crate::io::Read`/`Write` 泛型化，同样的代码既能驱动 TCP、TLS，也能驱动 UART 式字节流。

## 无 std 的哈希

```rust
use courierust::crypto::md5::md5_hex;
use courierust::crypto::sha256::sha256_hex;

let h = md5_hex(b"hello");    // "5d41402abc4b2a76b9719d911017c592"
let h = sha256_hex(b"hello"); // "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
```

这两个是 crate 里仅有的加密实现（给 JA3/JA4 用），都是小而查表驱动、零依赖。
