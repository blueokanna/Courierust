# courierust_server

HTTP 服务器，也是事件驱动调度器的家。默认情况下，空闲 / 半截 / 慢速连接挂在就绪轮询器上，**零 worker 占用**；就绪的连接按批派发给 event worker。TLS 和 HTTP/2 连接跑在阻塞的工作窃取池上。`ServerConfig::event_driven` 默认 `true`。

## 架构

```
accept 线程 ──> 事件循环（poller + 分类）──> event worker（按批）
                      │                                   │
                      └── TLS / h2 ──> 阻塞池              └── h1
```

- **Accept 线程**只 accept——从不读、从不 peek、从不睡、从不分类，慢客户端永远卡不住 accept 路径。
- **事件循环**把明文 HTTP 连接挂在 poller 上（Winsock `select` / POSIX `poll`），从前几个字节分类 TLS / h2 / h1，并回收 idle 连接。
- **Event worker** 跑一个增量请求解析器，能在上次停下的地方恢复——半截请求被挂回，而不是被握住。
- **TLS 和 HTTP/2** 走阻塞池，由 `handshake_timeout` / `h2_idle_timeout` / worker 数约束。

整个架构靠一个 **self-pipe** 串起来——一对回环 socket，读端注册进 poller，让入队的控制消息*入队的瞬间*就打断阻塞的 poll。poll 超时永远不会进请求延迟路径。完整故事，连同催生它的 5ms P99 尖峰，在 `blogs/03-self-pipe-event-scheduler.md`。

## worker 介入之前的防护

- 不完整的请求挂在 poller 上（零 worker）。
- 超过 `idle_timeout` 没动静的连接被回收。
- `max_connections` 直接封顶驻留连接数。
- keep-alive / SSE / slow-loris 羊群耗不干池——并发基准证明了：200 条空闲半开连接 + 2 个 worker 仍能 ~300µs 内服务一次探测，而旧的"一连接一池任务"模型直接整体阻塞。

## 边界

- 事件路径服务 HTTP/1.1。TLS 和 h2 按设计走阻塞池。
- `event_driven: false` 恢复旧模型——每连接一个池任务——供对比与调试。不建议生产用：空闲/慢速羊群会耗尽池。
- 长时间阻塞的同步 handler 会占住一个 worker（事件驱动与否都一样）——任何同步服务器的通病。流式请用 channel body。
- 同时服务 h2c 前导知识和 `h2c` Upgrade。

## 用法

```rust
use courierust::courierust_server::{Server, ServerConfig};
use courierust::courierust_http::{Request, Response};

let mut cfg = ServerConfig::default();
cfg.http2 = true; // 同端口 h2c + h1.1
let server = Server::bind_with_config("127.0.0.1:8080", cfg)?;

server.serve(|req: Request<Body>| -> Response<Body> {
    Response::with_status(200.into())
})?;
```

给 `ServerConfig::tls` 配上 `Identity` + ALPN，同一个服务器就说 HTTPS——见 `examples/https.rs`。
