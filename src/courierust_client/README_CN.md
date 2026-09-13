# courierust_client

多核 HTTP 客户端：按 authority 分组的 HTTP/1.1 keep-alive 连接池、由专用 driver 线程多路复用的 HTTP/2 连接、走内置 runtime 的 HTTP/3——当你请求 `https://` 时，全程跑在 crate 自己的 TLS 上。

## 模型

- **HTTP/1.1**——按 authority 的 keep-alive 池，有界复用。取用池连接前先做一次活性探测（服务器在空转期间已关掉的连接不付出任何代价：还没写入任何字节，即便是 `POST` 也不会发到死连接上）；请求途中连接死亡则**一次**新连接重试，且仅限于可重放的幂等方法（RFC 9110 §9.2.2），绝不重放 `POST`。每条连接拥有自己的读写缓冲区和 `Scratch`，稳态 keep-alive 请求**零按请求分配**、零 socket 重配。
- **HTTP/2**——每条连接由专用 driver 线程驱动，串行化线上访问的同时多路复用流。请求经 channel 到达；响应经每流 channel 流回。`max_connections_per_host` 按 authority 封顶存活连接；h2 池按 authority 共享。
- **HTTP/3**——`http3://`（以及 ALPN `h3`）路由进 H3 runtime 的 UDP reactor，支持池化连接复用。
- **WebSocket**——`courierust_client::ws::WebSocket` 通过 `ws://` 或 TLS（`wss://`）升级，提供 `send_text` / `send_binary` / `send_ping` / `read_message` / `close`，并支持子协议、Origin 头、压缩偏好与读超时，全部沿用同一个 `ClientConfig`。它与服务端共用组帧/UTF-8/关闭握手引擎（`courierust_ws`），两端强制的是同一套规则。
- **TLS**——`https://` 是一等公民：`TlsSettings { roots, verify, alpn, now, min_version, max_version }`，对着 crate 自己的 TLS 栈。

## 重要的细节

- **重定向**（301/302/303 → GET，307/308 保留方法与请求体）绝不跨 origin 转发 `Authorization` / `Cookie`（RFC 9110 §15.4）。
- **优先级**——`execute_priority(url, req, Priority { urgency, incremental })` 驱动 WUCS 调度器（见 `blogs/01`）。
- **worker 占用按连接而非按流**——一条带很多流的 h2 连接只占一个 worker，流永远不会把 worker 用量翻倍，也互不阻塞。
- **超时**——连接、握手（TLS）、读、整请求超时，全部可配。
- **WebSocket 的读超时就是 socket 超时。** `ClientConfig::read_timeout`（默认 60 s）对交互式流量是正确的存活机制，但 Windows 会在每次阻塞操作上收费：armed 状态下 256 KiB 的 WebSocket 批量推送大约**慢 2 倍**。批量传输的客户端应设 `read_timeout: None`，改用应用层存活判断——服务端就是这么做的（实测见 [`courierust_ws` README](../courierust_ws/README_CN.md)）。
- **h2c 前导知识**是选配（`cfg.http2 = true`）；服务端支持 `h2c` Upgrade。

## 诚实的话

一条 h2 连接**不会**随调用线程数线性扩展——driver 是单一串行化点。基准套件如实报告这一点（`h2_connections=1` 配 N 个并发流），README 的建议是：每条 h2 连接 4–8 个客户端 worker，再往上加连接而不是加 worker。

## H2 加权连接选择

当 `max_connections_per_host` 逼着你做选择时（cap 处所有连接都忙），h2 池选的是**加权负载**最低的连接，而不是单纯并发流最少的：

```
load(c) = active_streams + body_units(c) + ewma_service_ms(c)
```

- `active_streams`——在途请求数（派发 reservation）。
- `body_units(c)`——在途请求体字节数，按 64 KiB 折算。一条连接上挂着一个 1 MiB 上传，加权约 17 单位，而一个 header-only RPC 只有 1 单位——大上传不再藏在低流数后面（这就是"一个巨大 body 看起来跟一个小 RPC 一样便宜"的选择漏洞）。
- `ewma_service_ms(c)`——每请求服务时间（派发→响应）的 EWMA，封顶 10 ms，单个病态样本不会把连接钉死成永久慢；除数让延迟项保持温和，选择不会来回震荡。

账目按构造保证精确：`reserve(body_bytes)` 与 `release(body_bytes)` 在每条派发路径上成对（包括 driver 消失后的重试），所以连接在最后一个请求完成时精确回到 `idle`。idle 优先：空闲连接总是优先复用，**无论其 EWMA 历史如何**（空闲连接的 EWMA 只在有新样本时才衰减，纯加权最小选择会把它永远跳过）；延迟项只用于在*忙*连接之间打破平局。流式（`Body::Channel`）请求按 0 单位计——诚实的"未知大小"，不是猜测。这是 cap 处的*选择*策略，不改变单连接 wire 串行化的结构性上限。

## 用法

```rust
use courierust::courierust_client::{Client, ClientConfig};

let client = Client::new();
let resp = client.get("http://127.0.0.1:8080/")?;
println!("{}", String::from_utf8_lossy(&resp.body.collect()?));

let resp = client.post("http://127.0.0.1:8080/submit", b"hello")?;
```
