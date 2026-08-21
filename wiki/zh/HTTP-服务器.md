# HTTP 服务器

默认采用**事件驱动调度器**：accept 线程把 socket 交给事件循环，事件循环用就绪轮询器（Winsock `select` / POSIX `poll`）挂起空闲/半截的明文 HTTP 连接——大量 keep-alive / SSE / slow-loris 连接**零 worker 占用**。就绪连接交给少量事件 worker，由**增量式请求解析器**从断点继续解析；慢发送方重新挂回轮询器，不占 worker。TLS 与 HTTP/2 连接走**工作窃取线程池**，连接处理跨核并行。handler 就是一个普通函数，不需要实现任何框架类型。

## handler

handler 是任意 `Fn(Request<Body>) -> Response<Body> + Send + Sync + 'static`。闭包直接可用：

```rust
use courierust::courierust_body::Body;
use courierust::courierust_bytes::Bytes;
use courierust::courierust_http::request::Request;
use courierust::courierust_http::response::Response;

let handler = |req: Request<Body>| -> Response<Body> {
    let mut resp = Response::with_status(200.into());
    resp.body = Body::Bytes(Bytes::from(format!("path: {}", req.uri.as_str())));
    resp
};
```

复杂逻辑用结构体实现 `Handler` trait（字段是你自己的应用状态）：

```rust
use courierust::courierust_body::Body;
use courierust::courierust_bytes::Bytes;
use courierust::courierust_http::request::Request;
use courierust::courierust_http::response::Response;
use std::sync::Arc;

// `Db` 是你自己的应用类型，不是 crate 提供的。
// Handler 要求 Send + Sync，所以 Db 也必须满足。
struct App {
    db: Arc<dyn Db>,
}

impl courierust::courierust_server::Handler for App {
    fn handle(&self, req: Request<Body>) -> Response<Body> {
        match req.uri.as_str() {
            "/health" => Response::with_status(200.into()),
            _ => {
                let mut resp = Response::with_status(404.into());
                resp.body = Body::Bytes(Bytes::from_static(b"not found"));
                resp
            }
        }
    }
}
```

## 配置

```rust
use courierust::courierust_server::{Server, ServerConfig};
use std::time::Duration;

let cfg = ServerConfig {
    // 同一端口同时服务 HTTP/2（前导知识）与 HTTP/1.1。
    http2: true,
    // worker 线程数；0 = 逻辑核数。
    threads: 0,
    read_timeout: Some(Duration::from_secs(120)),
    max_header_list: 1 << 20,
    max_body: 16 * 1024 * 1024,
};
```

## 阻塞式运行

```rust
let server = Server::bind_with_config("0.0.0.0:8080", cfg)?;
server.serve(app)?; // 永久阻塞
```

## 后台运行（测试 / 嵌入场景）

```rust
let server = Server::bind_with_config("127.0.0.1:0", cfg)?;
let addr = server.local_addr()?;      // 实际绑定端口
let handle = server.serve_background(app)?;

// ... 继续做别的事 / 跑测试 ...
// 丢弃句柄即停止 accept；已建立的连接正常排空。
drop(handle);
```

## 流式响应体

返回 `Body::Channel`，服务器带流控背压地流式发送：只有连接有发送窗口时才从 channel 取块。慢客户端不会撑爆内存。

```rust
let handler = |_req: Request<Body>| -> Response<Body> {
    let (tx, body) = courierust::courierust_body::channel();
    std::thread::spawn(move || {
        for i in 0..100 {
            // tx.send 在接收端被丢弃时失败，返回 Result。
            let _ = tx.send(Bytes::from(format!("event {i}\n")));
        }
        drop(tx); // 关闭发送端 = 流结束
    });
    let mut resp = Response::with_status(200.into());
    resp.body = body;
    resp
};
```

中途出错用 `tx.fail(err)` —— 连接会以 `INTERNAL_ERROR` 重置该流。

## 注意

- 无响应体的 HTTP/1.1 响应会显式补 `Content-Length: 0`；长度未知时发 chunked。
- 明文 HTTP/1.1 全平台默认走事件调度器：半截请求挂在轮询器上（零 worker），超过 `ServerConfig::idle_timeout` 的空转连接被回收，`max_connections` 封顶驻留连接数。TLS 与 HTTP/2 连接走阻塞池，由 `handshake_timeout` / `h2_idle_timeout` 约束。设 `event_driven: false` 恢复旧的每连接一池任务模型。
- **同步 handler** 阻塞多久就占住事件 worker 多久——与任何同步服务器一致。流式场景用 channel body（`Body::Channel`），worker 可及时归还。
- gRPC 服务器就是这层之上的薄封装，见 [gRPC 使用指南](gRPC-使用指南)。
