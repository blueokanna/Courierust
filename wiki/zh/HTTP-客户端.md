# HTTP 客户端

客户端按 authority 共享有上限的连接池。HTTP/2 请求由每条连接独立的 driver 负责多路复用，并按当前 reservation 数选择负载最小的连接；`max_connections_per_host` 控制并发压力下可打开的独立 driver 数量。这是按连接感知的并发模型，不承诺单条 HTTP/2 连接会随调用线程线性扩展。

## 配置

```rust
use courierust::courierust_client::{Client, ClientConfig};
use std::time::Duration;

let cfg = ClientConfig {
    // 优先用 HTTP/2（h2c 前导知识）；false 则用 HTTP/1.1。
    http2: true,
    // 每个 host 缓存的 keep-alive(h1)/多路复用(h2) 连接数上限。
    max_connections_per_host: 4,
    // 超时：连接 / 单次读。
    connect_timeout: Some(Duration::from_secs(10)),
    read_timeout: Some(Duration::from_secs(60)),
    // 自动跟随重定向（301/302/303 自动转 GET，见 RFC 9110）。
    max_redirects: 10,
    // 请求携带的 User-Agent；None 则不发送。
    user_agent: Some("my-app/1.0".to_string()),
    // 防御性限制：接受的对端头列表与响应体大小上限。
    max_header_list: 1 << 20,
    max_body: 16 * 1024 * 1024,
};

let client = Client::with_config(cfg);
// Client 可廉价 clone，内部共享连接池。
let c2 = client.clone();
```

`Client::new()` 等价于全默认配置。

## GET

```rust
let resp = client.get("http://127.0.0.1:8080/health")?;
println!("status: {}", resp.status.as_u16());
// Body::collect() 阻塞直到整个响应体收完。
let body = resp.body.collect()?;
println!("body: {}", body.to_str()?);
```

## POST

`post` 接受任何能转成 `Body` 的类型：`Bytes`、`Vec<u8>`、`String`、`&'static str`、`&'static [u8]`：

```rust
let resp = client.post("http://127.0.0.1:8080/submit", "raw text payload")?;
let resp = client.post("http://127.0.0.1:8080/submit", vec![1u8, 2, 3])?;
```

## 带请求头的 Request 与响应检查

```rust
use courierust::courierust_body::Body;
use courierust::courierust_bytes::Bytes;
use courierust::courierust_http::header::{HeaderName, HeaderValue};
use courierust::courierust_http::method::Method;
use courierust::courierust_http::request::Request;

let mut req = Request::new(Method::POST, "/api/items?page=2");
req.headers.insert(
    HeaderName::from_lowercase("content-type"),
    HeaderValue::from_static("application/json"),
);
req.headers.insert(
    HeaderName::from_lowercase("authorization"),
    HeaderValue::from_bytes(b"Bearer abc123")?,
);
req.body = Body::Bytes(Bytes::from(r#"{"name":"courierust"}"#));

let resp = client.execute("http://127.0.0.1:8080", req)?;
println!("version: {}", resp.version);
println!("x-request-id: {:?}", resp.headers.get("x-request-id"));
```

注意：

- 请求的 `uri` 是**路径**；scheme/host/port 来自 `execute` 传入的 URL。
- `HeaderName::from_lowercase` 用于已知的小写静态名；`from_bytes` 会自动校验并转小写。
- 响应头保持原始顺序；`get` 返回同名字段的第一个。

## 重定向

默认开启，由 `max_redirects` 限制次数。`301`/`302`/`303` 自动转为 `GET`（RFC 9110）并丢弃请求体。绝对地址、协议相对（`//host/...`）、相对路径三种 `Location` 都支持：

```rust
// 最多自动跟随 10 跳，最终响应原样返回。
let resp = client.get("http://short.example/start")?;
```

## RFC 9218 优先级（HTTP/2）

HTTP/2 下可以给每个请求指定优先级。服务器端用 WUCS 调度器调度流：urgency `0..=7`（0 最高），`incremental` 表示数据到达即可消费的流。

```rust
use courierust::courierust_h2::priority::Priority;

// 从线上格式解析（"u=1, i"）或直接构造：
let prio = Priority { urgency: 1, incremental: true };

let mut req = Request::new(Method::GET, "/big-download");
let resp = client.execute_priority("http://127.0.0.1:8080", req, prio)?;
```

`Priority` 实现了 `Default`（urgency 3、非增量）、`Display`（`u=3`），也支持 `Priority::parse(b"u=1, i")`。

## 流式响应体（HTTP/2）

流式（`Channel`）响应体用 `try_next_chunk` 逐块消费，适合 SSE 或大文件下载，不需要整包缓冲：

```rust
let resp = client.get("http://127.0.0.1:8080/events")?;
let mut body = resp.body;
while let Some(chunk) = body.try_next_chunk()? {
    // chunk: courierust::courierust_bytes::Bytes
    eprintln!("chunk: {} bytes", chunk.len());
}
```

## 错误处理

所有可失败调用返回 `courierust::Result<T>`，错误类型为 `courierust::Error`：

```rust
match client.get("http://127.0.0.1:9/") {
    Ok(resp) => println!("ok: {}", resp.status),
    Err(e) => {
        println!("kind: {:?}", e.kind); // Error.kind 是公开字段
        println!("message: {}", e);
    }
}
```

`Error` 可转换为 `std::io::Error`（用于 `?` 冒泡），并带公开的 `kind` 字段供程序化处理。

## 你需要知道的限制

- **配置后支持 HTTPS**。客户端默认 `tls: None`，因此默认会拒绝 `https://`；通过 `ClientConfig::tls` 提供 `RootStore`，或使用 `Client::with_tls_roots` 启用内置 TLS 1.2 + 1.3。crate 不内置 CA 根证书。ALPN 必须与 `ClientConfig::http2` 一致：HTTP/2 使用 `h2`，HTTP/1.1 使用 `http/1.1`。
- **HTTP/2 并发取决于连接策略**。每条连接由一个 driver 负责复用多个 stream；需要独立 HTTP/2 driver 时提高 `max_connections_per_host`，并针对实际配置观察完整延迟尾部。
- **流式请求体仅 HTTP/2 支持**。`Client::execute` 会把 `Body::Channel` 请求体先完整读进内存再发送；真正的客户端上传流式使用 `execute_h2_stream`。
