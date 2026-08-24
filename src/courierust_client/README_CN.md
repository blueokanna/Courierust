# courierust_client

多核 HTTP 客户端：按 authority 分组的 HTTP/1.1 keep-alive 连接池、由专用 driver 线程多路复用的 HTTP/2 连接、走内置 runtime 的 HTTP/3——当你请求 `https://` 时，全程跑在 crate 自己的 TLS 上。

## 模型

- **HTTP/1.1**——按 authority 的 keep-alive 池，有界复用。每条连接拥有自己的读写缓冲区和 `Scratch`，稳态 keep-alive 请求**零按请求分配**、零 socket 重配。
- **HTTP/2**——每条连接由专用 driver 线程驱动，串行化线上访问的同时多路复用流。请求经 channel 到达；响应经每流 channel 流回。`max_connections_per_host` 按 authority 封顶存活连接；h2 池按 authority 共享。
- **HTTP/3**——`http3://`（以及 ALPN `h3`）路由进 H3 runtime 的 UDP reactor，支持池化连接复用。
- **TLS**——`https://` 是一等公民：`TlsSettings { roots, verify, alpn, now, min_version, max_version }`，对着 crate 自己的 TLS 栈。

## 重要的细节

- **重定向**（301/302/303 → GET）绝不跨 origin 转发 `Authorization` / `Cookie`（RFC 9110 §15.4）。
- **优先级**——`execute_priority(url, req, Priority { urgency, incremental })` 驱动 WUCS 调度器（见 `blogs/01`）。
- **worker 占用按连接而非按流**——一条带很多流的 h2 连接只占一个 worker，流永远不会把 worker 用量翻倍，也互不阻塞。
- **超时**——连接、握手（TLS）、读、整请求超时，全部可配。
- **h2c 前导知识**是选配（`cfg.http2 = true`）；服务端支持 `h2c` Upgrade。

## 诚实的话

一条 h2 连接**不会**随调用线程数线性扩展——driver 是单一串行化点。基准套件如实报告这一点（`h2_connections=1` 配 N 个并发流），README 的建议是：每条 h2 连接 4–8 个客户端 worker，再往上加连接而不是加 worker。

## 用法

```rust
use courierust::courierust_client::{Client, ClientConfig};

let client = Client::new();
let resp = client.get("http://127.0.0.1:8080/")?;
println!("{}", String::from_utf8_lossy(&resp.body.collect()?));

let resp = client.post("http://127.0.0.1:8080/submit", b"hello")?;
```
