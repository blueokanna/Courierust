# HTTP 服务器

服务器把每个 accept 到的连接作为任务投递到**工作窃取线程池**，连接处理跨核并行。handler 就是一个普通函数，不需要实现任何框架类型。

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
- `Server::serve` 把每个连接作为一个池任务。慢请求会占住一个 worker 直到读完——对多数场景够用；超长连接可能需要你自己拆事件循环。
- gRPC 服务器就是这层之上的薄封装，见 [gRPC 使用指南](gRPC-使用指南)。
