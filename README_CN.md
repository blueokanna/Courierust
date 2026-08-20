# Courierust - [English Doc](README.md)

> 一个零依赖、协议自研的 HTTP/1.1 + HTTP/2 + gRPC 协议栈。

> 中英文手把手教程见 [Wiki](https://github.com/blueokanna/Courierust/wiki)。

`courierust` 的协议核心（`http` / `hpack` / `h2` / `fingerprint` / `crypto` / `bytes` / `io`）在 `no_std + alloc` 下即可编译，**不依赖任何第三方库**。`std` feature（默认开启）在此基础上补上多线程网络层：工作窃取线程池、TCP 适配、客户端、服务器与 gRPC。

这不是对某个现成库的封装，帧编解码、HPACK 头压缩、流状态机、流控、优先级调度、指纹构造都是从头实现的。

## 为什么会有这个项目

常见的 Rust HTTP 生态（hyper / h2 / h3 等）能力很强，但依赖树很深，且往往把 `no_std`、多核亲和、以及「客户端看起来像什么浏览器」这类问题留给使用者自己解决。这个仓库的目标是：

- 协议层与平台完全解耦：核心代码不碰 `std`，`std` 只负责线程、TCP 和时钟；
- 多核是真的多核：连接池按 worker 分片、HTTP/2 连接跨 worker 分发、任务用工作窃取调度，而不是一把大锁串起来；
- 协议细节按 RFC 实现并对照公开测试向量验证过，不是「能跑就行」的玩具。

## 特性

### 协议核心（no_std + alloc，零依赖）

- **HTTP/1.1**：请求/响应解析与序列化，keep-alive、分块传输、`100-continue` 等语义。
- **HTTP/2（RFC 9113）**：
  - 完整帧编解码（DATA / HEADERS / PRIORITY / RST_STREAM / SETTINGS / PUSH_PROMISE / PING / GOAWAY / WINDOW_UPDATE / CONTINUATION）；
  - 每流与连接两级流控，窗口按帧推进；
  - 流状态机严格按 §5.1 迁移，非法迁移直接 `PROTOCOL_ERROR`；
  - 流优先级（RFC 9218）：解析 `Priority` 头 / `PRIORITY_UPDATE` 帧（类型 `0x10`），配合自研 **WUCS 调度器**（见下）。
- **HPACK（RFC 7541）**：
  - 静态表 61 项 + 动态表 + 哈希加速索引查找；
  - 8-bit 两级查表 Huffman 解码（构建期查表），解码走快速路径；
  - 对照 RFC C.2–C.6 全部官方向量逐字节验证。
- **指纹**：
  - `TlsProfile` 描述一次 TLS ClientHello 的关键参数；自带的 MD5 / SHA-256 实现（无依赖）；
  - **JA3**：`ja3_hash()` 产出标准 32 位十六进制指纹，与公开的 Chrome 记录一致；
  - **JA4**：`ja4()` 产出 `t13d1516h2_…` 四段式指纹，与规范示例一致；
  - **Chrome HTTP/2 指纹**：SETTINGS 项、WINDOW_UPDATE 初值、帧序、头字段排序都按 Chrome 行为复刻，可直接喂给外置 TLS 层。

### std 网络层

- **工作窃取线程池**（`pool`）：每个 worker 一条本地 LIFO 栈 + 全局 FIFO 窃取队列；任务可嵌套提交，窃取时优先挑空闲最久的 worker。
- **客户端**（`client`）：
  - HTTP/1.1 keep-alive 连接池按 authority 分组，按 worker 分片（各自持锁，避免全局争用）；
  - HTTP/2 连接同样按 worker 分片 + 轮询分发，多路复用；
  - 重定向跟随（301/302/303 自动转 GET）、超时、`User-Agent` 等配置项。
- **服务器**（`server`）：每个 accept 的连接作为任务投递到工作窃取池，连接处理跨核并行。
- **gRPC**（`grpc`）：HTTP/2 + 长度前缀消息帧 + `grpc-status`/`grpc-message` 处理；protobuf 编解码刻意留给你（实现 `EncodeMessage` / `DecodeMessage`，或直接用字节 API）。
- **流式响应**（`body`）：channel 背靠背的 `Body::Channel`，服务器可跨线程推送响应体块。

## 多核与调度：真正花心思的地方

纯 `no_std` 协议核心很多人写过，真正难的是让它在多核上有真实收益。

### WUCS —— Weighted-Urgency Calendar Scheduler（RFC 9218）

RFC 9218 用 8 个 urgency 级别替代了旧版依赖树。我们把它实现为 8 个 bucket 的日历式调度器：

- 每个 bucket 是一个 **DRR（Deficit Round Robin）** 类别，配额按字节累计，高 urgency 再忙也饿不死低 urgency（RFC 9218 §10 明确要求防饥饿）；
- bucket 内 **incremental** 流轮流调度（带宽随数据到达共享），**非 incremental** 流按流 ID FIFO——与 RFC 建议的升序一致；
- 每帧选择是 **O(1)**：固定 8 桶扫描，不做任何排序或堆操作，这在热连接上每帧都付得起。

`Priority { urgency, incremental }` 可以解析自 `Priority` 头 / `PRIORITY_UPDATE` 帧，也可以通过 `Client::execute_priority` 直接指定。

### BCR —— Batched Credit Reflow 流控

传统实现每收一帧就回一个 `WINDOW_UPDATE`，控制帧开销占比可观。BCR 把已收数据批量累积，攒够一批再回一次信用，控制帧数量降一个量级。

### 连接池分片

客户端连接池不是一把全局锁下的 `HashMap`，而是每个 worker 一份分片、各自持锁；HTTP/2 连接按 worker 轮询分发。请求基本不跨 worker 抢锁，扩展性随核数走。

## 快速上手

### 客户端

```rust
use courierust::client::{Client, ClientConfig};

let client = Client::new();

// GET
let resp = client.get("http://127.0.0.1:8080/")?;
println!("status={} body={}", resp.status, String::from_utf8_lossy(&resp.body.collect()?));

// POST
let resp = client.post("http://127.0.0.1:8080/submit", "hello".as_bytes())?;
```

指定 HTTP/2（h2c 前导知识）与优先级：

```rust
use courierust::h2::priority::Priority;

let mut cfg = ClientConfig::default();
cfg.http2 = true;

let client = Client::with_config(cfg);
let prio = Priority { urgency: 1, incremental: true };
let resp = client.execute_priority("http://127.0.0.1:8080/api", request, prio)?;
```

### 服务器

```rust
use courierust::server::{Server, ServerConfig};
use courierust::http::request::Request;
use courierust::http::response::Response;
use courierust::body::Body;

let mut cfg = ServerConfig::default();
cfg.http2 = true; // 同时服务 h2c 与 h1.1
let server = Server::bind_with_config("127.0.0.1:8080", cfg)?;

server.serve(|req: Request<Body>| -> Response<Body> {
    let mut resp = Response::with_status(200.into());
    resp.body = Body::Bytes(format!("path: {}", req.uri.as_str()).into());
    resp
})?;
```

### gRPC

```rust
use courierust::grpc::{GrpcClient, GrpcServer};
use courierust::bytes::Bytes;

// 服务器端：实现 Service（或直接传闭包）
let server = GrpcServer::bind("127.0.0.1:50051", |method: &str, req: Bytes| {
    Ok(Bytes::from(format!("echo({method}): {}", String::from_utf8_lossy(&req))))
})?;
let _h = server.serve_background()?;

// 客户端
let client = GrpcClient::new("http://127.0.0.1:50051")?;
let reply = client.call("helloworld.Greeter/SayHello", Bytes::from("world"))?;
```

## HTTPS（内置 TLS 1.3）

自 0.1 起，本 crate 自带一套零依赖、从零实现的 TLS 1.3（RFC 8446），
因此 `https://` 成为同一套客户端/服务端的一等公民能力：

```rust
use courierust::client::{Client, ClientConfig, TlsSettings as ClientTls};
use courierust::server::{Server, ServerConfig, TlsSettings as ServerTls};

// 服务端：用你的证书链 + 私钥开 HTTPS。
let identity = courierust::tls::Identity {
    cert_chain: vec![cert_der],        // 叶子在前（DER）
    private_key: key_der,              // PKCS#8 或 PKCS#1（DER）
    is_rsa: false,                     // Ed25519/ECDSA 为 false
};
let server_cfg = ServerConfig {
    http2: true,                        // TLS 之上同时支持 h2 与 HTTP/1.1（ALPN）
    tls: Some(ServerTls {
        identity,
        alpn: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
    }),
    ..Default::default()
};

// 客户端：信任你的根证书并开启 TLS。
let mut roots = courierust::tls::RootStore::new();
roots.add_der(root_der);                // 或用 RootStore::add_pem(...)
let client_cfg = ClientConfig {
    tls: Some(ClientTls {
        roots,
        verify: true,
        alpn: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        now: unix_now_secs,             // 证书有效期校验用
    }),
    ..Default::default()
};
let client = Client::with_config(client_cfg);
let resp = client.get("https://example.com/")?;
```

支持的 TLS 1.3 配置：`TLS_CHACHA20_POLY1305_SHA256`、
`TLS_AES_128_GCM_SHA256`、`TLS_AES_256_GCM_SHA384`；X25519 密钥交换；
RSA-PSS / RSA-PKCS#1 v1.5 / ECDSA P-256 / Ed25519 证书签名；完整的
X.509 链校验（有效期、名称链、签名验证、basic-constraints /
key-usage、RFC 6125 主机名校验含 IP SAN、可插拔根证书库）。
`cargo run --example https` 可跑一个自签名证书的端到端示例。

## 指纹：让连接「看起来像」 Chrome

TLS 握手参数完全由你掌控（包括内置 TLS 层）：

```rust
use courierust::fingerprint::{chrome_tls_profile, ja3_hash, ja4, h2::ChromeH2Fingerprint};

let profile = chrome_tls_profile();
assert_eq!(ja3_hash(&profile), "cd08e31494f9531f560d64c695473da9");
assert_eq!(ja4(&profile), "t13d1516h2_8daaf6152771_e5627efa2ab1");

// HTTP/2 侧：直接得到一套 Chrome 形状的 SETTINGS / 帧序 / 头序
let fp = ChromeH2Fingerprint::chrome();
let mut settings = fp.settings_entries(); // 含 WINDOW_UPDATE、MAX_FRAME_SIZE 等
let ordered = fp.order_headers_chrome(&fields); // 按 Chrome 的头序重排
```

## no_std 用法

协议核心不依赖 `std`。在你的 `Cargo.toml` 里：

```toml
[dependencies]
courierust = { version = "0.1", default-features = false }
```

`--no-default-features` 构建只编译协议核心，可用于嵌入式 / 内核态。网络层需要 `std` feature（默认开启）。

## 诚实的边界

这个仓库刻意不做的，以及你接手前应该知道的：

- **没有 HTTP/3 / QUIC**。零外部依赖意味着没有可用的 QUIC 实现（QUIC 需要用户态 UDP 栈 + TLS 1.3——TLS 部分已有，传输层没有）。
- **TLS 暂无 PSK / 0-RTT 恢复 / session ticket / key update**。每次都做完整 1-RTT 握手；对端发来的 NewSessionTicket 会被忽略。
- **事件驱动服务器仅限 Windows 且只处理 HTTP/1.1**。Windows 上 `ServerConfig::event_driven`（默认开启）把空闲明文 HTTP 连接挂在轮询器上，少量 worker 即可服务大量 idle keep-alive / SSE / 长轮询连接；TLS 与 HTTP/2 连接仍走阻塞池模型。非 Windows 平台回退到每连接一任务的池模型。
- **请求体流式上传目前只在 HTTP/2 下可靠**（h2 天然分帧）。HTTP/1.1 的请求体要么一次性给全（`Body::Bytes`），要么你自己拼 chunked。
- **gRPC 不含 protobuf**。消息编解码需要你实现 codec trait 或接你自己的 protobuf 生成代码。
- **长时间阻塞的同步 handler 会占住一个 worker**（事件驱动与否都一样）——任何同步服务器的通病；流式场景用 channel 响应体。
- 客户端重定向、keep-alive 复用等策略以「正确」为先，未做激进调优。

## 目录结构

```
src/
├── http/        # HTTP/1.1 消息模型（请求/响应/头/URI/状态码）      [no_std]
├── hpack/       # HPACK：表驱动 Huffman + 静态/动态索引表           [no_std]
├── h2/          # HTTP/2 帧、SETTINGS、流状态机、流控、WUCS、PRIORITY_UPDATE [no_std]
├── fingerprint/ # JA3 / JA4 / Chrome HTTP/2 指纹                    [no_std]
├── crypto/      # 自带 MD5 / SHA-256（指纹用）                      [no_std]
├── bytes/       # 字节缓冲（BytesMut）                              [no_std]
├── io/          # Read/Write trait（no_std 版）                     [no_std]
├── error/       # 统一错误类型
├── pool/        # 工作窃取线程池                                    [std]
├── net/         # TCP → io trait 适配                               [std]
├── body/        # 流式响应体（channel）                             [std]
├── h1/          # HTTP/1.1 线上编解码                                [std]
├── client/      # h1 连接池 + h2 驱动                                [std]
├── server/      # 基于工作窃取池的服务器                             [std]
└── grpc/        # gRPC 帧 + 状态 + codec trait                       [std]
```

## 测试

- 单元测试 49 个：覆盖 HPACK 全部 RFC 向量（C.2/C.3/C.4/C.6）、Huffman 编解码、帧编解码、状态机、流控、WUCS 调度、JA3/JA4 公开记录比对、指纹解析。
- 集成测试 9 个：真实 TCP 环回上的 h1/h2 请求往返、keep-alive 复用、chunked、重定向、h2 并发多路复用、流式响应、gRPC unary 与错误状态。

```bash
cargo test                 # 全部测试
cargo build --no-default-features   # 验证协议核心零警告编译
```

## 许可

Apache-2.0。
