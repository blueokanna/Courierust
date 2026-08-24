# Courierust - [English Doc](README.md)

<p align="center">
  <img src="assets/Courierust.png" alt="高性能 Rust 网络传输栈" width="20%" />
</p>

> 一个零依赖、协议自研的 HTTP/1.1 + HTTP/2 + gRPC 协议栈。

> 中英文手把手教程见 [Wiki](https://github.com/blueokanna/Courierust/wiki)。

`courierust` 的协议核心（`courierust_http` / `courierust_hpack` / `courierust_h2` / `courierust_fingerprint` / `courierust_crypto` / `courierust_bytes` / `courierust_io`）在 `no_std + alloc` 下即可编译，**不依赖任何第三方库**。`std` feature（默认开启）在此基础上补上多线程网络层：工作窃取线程池、TCP 适配、客户端、服务器与 gRPC。

这不是对某个现成库的封装，帧编解码、HPACK 头压缩、流状态机、流控、优先级调度、指纹构造都是从头实现的。

## 为什么会有这个项目

常见的 Rust HTTP 生态（hyper / h2 / h3 等）能力很强，但依赖树很深，且往往把 `no_std`、多核亲和、以及「客户端看起来像什么浏览器」这类问题留给使用者自己解决。这个仓库的目标是：

- 协议层与平台完全解耦：核心代码不碰 `std`，`std` 只负责线程、TCP 和时钟；
- 多核是真的多核（在模型范围内）：服务端连接通过工作窃取池调度；客户端连接池按 authority 共享，HTTP/2 请求按 reservation 选择负载最小的 driver，并由 `max_connections_per_host` 控制独立连接上限。**worker 占用按连接计**：一条 HTTP/2 连接上的任意多个流（慢流、SSE、gRPC 服务端流）只占同一个 worker，流之间互不阻塞。**事件驱动调度器（全平台默认）**把空闲/半截明文 HTTP 连接挂在就绪轮询器上，慢连接羊群不再耗尽 worker；`idle_timeout` 回收空转连接，`max_connections` 封顶驻留连接数。
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

- **工作窃取线程池**（`courierust_pool`）：每个 worker 一条本地 LIFO 栈 + 全局 FIFO 窃取队列；任务可嵌套提交，窃取时优先挑空闲最久的 worker。
- **客户端**（`courierust_client`）：
  - HTTP/1.1 keep-alive 连接池按 authority 分组并有上限；
  - HTTP/2 连接由独立 driver 多路复用，按 reservation 选择负载最小的连接并受 `max_connections_per_host` 限制；
  - 重定向跟随（301/302/303 自动转 GET）、超时、`User-Agent` 等配置项。
- **服务器**（`courierust_server`）：每个 accept 的连接作为任务投递到工作窃取池，连接处理跨核并行。
- **gRPC**（`courierust_grpc`）：HTTP/2 + 长度前缀消息帧 + `grpc-status`/`grpc-message` 处理；protobuf 编解码刻意留给你（实现 `EncodeMessage` / `DecodeMessage`，或直接用字节 API）。
- **流式响应**（`courierust_body`）：channel 背靠背的 `Body::Channel`，服务器可跨线程推送响应体块。

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

### 连接池所有权与调度

每条客户端连接拥有自己的 codec 缓冲区；HTTP/2 连接还拥有一个串行化 wire 访问并复用 stream 的 driver。连接池按 authority 管理，reservation 反映正在 dispatch 的请求，`max_connections_per_host` 是独立连接上限。单条 HTTP/2 连接不会因为调用线程增加就线性扩展，应结合并发基准和延迟尾部选择连接数。

## 快速上手

### 客户端

```rust
use courierust::courierust_client::{Client, ClientConfig};

let client = Client::new();

// GET
let resp = client.get("http://127.0.0.1:8080/")?;
println!("status={} body={}", resp.status, String::from_utf8_lossy(&resp.body.collect()?));

// POST
let resp = client.post("http://127.0.0.1:8080/submit", "hello".as_bytes())?;
```

指定 HTTP/2（h2c 前导知识）与优先级：

```rust
use courierust::courierust_h2::priority::Priority;

let mut cfg = ClientConfig::default();
cfg.http2 = true;

let client = Client::with_config(cfg);
let prio = Priority { urgency: 1, incremental: true };
let resp = client.execute_priority("http://127.0.0.1:8080/api", request, prio)?;
```

### 服务器

```rust
use courierust::courierust_server::{Server, ServerConfig};
use courierust::courierust_http::request::Request;
use courierust::courierust_http::response::Response;
use courierust::courierust_body::Body;

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
use courierust::courierust_grpc::{GrpcClient, GrpcServer};
use courierust::courierust_bytes::Bytes;

// 服务器端：实现 Service（或直接传闭包）
let server = GrpcServer::bind("127.0.0.1:50051", |method: &str, req: Bytes| {
    Ok(Bytes::from(format!("echo({method}): {}", String::from_utf8_lossy(&req))))
})?;
let _h = server.serve_background()?;

// 客户端
let client = GrpcClient::new("http://127.0.0.1:50051")?;
let reply = client.call("helloworld.Greeter/SayHello", Bytes::from("world"))?;
```

## HTTPS（内置 TLS 1.2 + TLS 1.3）

自 0.1 起，本 crate 自带一套零依赖、从零实现的 TLS 栈——**TLS 1.3（RFC 8446）与 TLS 1.2（RFC 5246 / RFC 8422）**——因此 `https://` 成为同一套客户端/服务端的一等公民能力：

```rust
use courierust::courierust_client::{Client, ClientConfig, TlsSettings as ClientTls};
use courierust::courierust_server::{Server, ServerConfig, TlsSettings as ServerTls};

// 服务端：用你的证书链 + 私钥开 HTTPS。
let identity = courierust::courierust_tls::Identity {
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
let mut roots = courierust::courierust_tls::RootStore::new();
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

支持的 TLS 配置：

- **TLS 1.3（RFC 8446）：** `TLS_CHACHA20_POLY1305_SHA256`、
  `TLS_AES_128_GCM_SHA256`、`TLS_AES_256_GCM_SHA384`；X25519 密钥交换。
- **TLS 1.2（RFC 5246 / RFC 8422）：** 仅 AEAD 的 ECDHE 套件——
  `ECDHE-ECDSA-AES128-GCM-SHA256`、`ECDHE-ECDSA-AES256-GCM-SHA384`、
  `ECDHE-ECDSA-CHACHA20-POLY1305-SHA256` 以及对应的三个 `ECDHE-RSA-*`（
  secp256r1 ECDHE）。CBC/HMAC、静态 RSA 与 RC4 套件永不提供——记录层只
  实现 AEAD。RFC 5746 `renegotiation_info` 指示器会发送并回显；X25519
  只在同时提供 TLS 1.3 时声明（纯 TLS 1.2 的 ClientHello 只声明
  secp256r1，TLS 1.2 服务器永远不会选出客户端无法完成的群）。

两个版本共享同一套身份、证书链校验与信任模型：RSA-PSS /
RSA-PKCS#1 v1.5 / ECDSA P-256 / P-384 / Ed25519 证书签名；完整的 X.509
链校验（有效期、名称链、签名验证、basic-constraints / key-usage、RFC
6125 主机名校验含 IP SAN 与 CVE-2025-61727 排除子树通配符规则、可插拔
根证书库）。

**版本窗口完全可配置。** 客户端与服务端的 `TlsSettings::min_version` /
`max_version`（默认 `Tls12..=Tls13`）控制提供与协商的范围。两端都钉到
`Tls13` 即恢复纯 TLS 1.3 策略；接受过 TLS 1.3 客户端的 TLS 1.2 服务器
仍会把 RFC 8446 §4.1.3 降级哨兵写进 ServerHello 随机数，使客户端能检测
到降级；纯 TLS 1.3 客户端遇到 TLS 1.2 ServerHello 会拒绝且绝不静默降
级。从不提供 0-RTT / 会话恢复 / PSK。QUIC 必须协商 ALPN `h3`；HTTPS
的 ALPN 必须是 `h2` 或 `http/1.1`。
`cargo run --example https` 可跑一个自签名证书的端到端示例；`cargo run --example h3` 是 HTTP/3（QUIC v1 + TLS 1.3）端到端示例（冷连接 vs 池化复用、大响应流控、并发多路复用、证书拒绝）；`cargo run --example grpc_streaming` 演示 gRPC 服务端流/客户端流/双向流、deadline、gzip 压缩协商与元数据/拦截器。

## 指纹：让连接「看起来像」 Chrome

TLS 握手参数完全由你掌控（包括内置 TLS 层）：

```rust
use courierust::courierust_fingerprint::{chrome_tls_profile, ja3_hash, ja4, h2::ChromeH2Fingerprint};

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

## 设计限制

这个仓库刻意不做的，以及你接手前应该知道的：

- **HTTP/3 / QUIC 已有零依赖的内置路径，但协议边界必须如实理解**。`courierust_h3` 通过 std UDP reactor 运行 HTTP/3 请求/响应，包含 QUIC v1 包保护、内置 TLS 1.3、ALPN `h3`、有界 CRYPTO/stream 重组、Retry 完整性校验与 token 绑定的地址验证、Version Negotiation、验证前 3x anti-amplification、ACK range、使用新包号的重传、RTT/RTO 采样、有界拥塞窗口、控制/QPACK 流、trailer 与 GOAWAY 校验。它还不是完整的互联网级 QUIC 实现：完整 PTO/时间阈值丢包恢复、动态本地 `MAX_DATA`/`MAX_STREAM_DATA` credit 更新、连接迁移与路径验证、stateless reset、0-RTT/session ticket、自动及双向 key update、QPACK blocked-stream acknowledgement，以及独立实现互操作仍需实现和专门证据。在这些缺口关闭前，不应宣称对外普遍互通。
- **TLS 暂无 PSK / 0-RTT 恢复 / session ticket / key update，也无双向 mTLS**。每次都做完整 1-RTT 握手；对端发来的 NewSessionTicket 会被忽略；TLS 1.2 session id 会携带但从不用于恢复；服务端不请求客户端证书。基准里的 TLS 行因此如实报告 `session_resumption=n/a`。
- **事件驱动服务器全平台默认开启，只处理 HTTP/1.1**。`ServerConfig::event_driven`（默认 `true`）把空闲明文 HTTP 连接挂在轮询器上（Winsock `select` / POSIX `poll`），少量 worker 即可服务大量 idle keep-alive / SSE / 长轮询连接；TLS 与 HTTP/2 连接仍走阻塞池模型（由 `handshake_timeout`、`h2_idle_timeout` 与 worker 数共同约束）。设为 `false` 恢复旧的**每连接一池任务**模型；该路径已不建议用于生产——空闲/慢连接群会耗尽池——仅作对比与调试，默认事件路径用 `max_connections`（连接上限）与 `idle_timeout` 约束资源。
- **请求体流式上传目前只在 HTTP/2 下可靠**（h2 天然分帧）。HTTP/1.1 的请求体要么一次性给全（`Body::Bytes`），要么你自己拼 chunked。
- **gRPC 不含 protobuf、`.proto` 代码生成与 `grpc.reflection`**。消息编解码需要你实现 codec trait 或接你自己的 protobuf 生成代码；reflection 需要 protobuf 模式清单，属外部职责。
- **长时间阻塞的同步 handler 会占住一个 worker**（事件驱动与否都一样）——任何同步服务器的通病；流式场景用 channel 响应体。worker 占用**按连接而非按流**：一条连接上的任意空闲流只占同一个 worker，慢流不阻塞同连接其他流——两者均有集成测试覆盖。
- **HTTPS 是一等公民**：客户端与服务端内置从零实现的 TLS 1.2 + TLS 1.3；`https://` 需要自备根证书库（无内置 CA）。**ALPN 强制一致**：配置 h2 的客户端连到协商出 `http/1.1` 的服务器，或对方**完全未协商 ALPN**（RFC 9113 §3.3 要求 TLS 上必须用 ALPN `h2`），都会得到明确错误而非静默协议错乱。
- 客户端重定向、keep-alive 复用等策略以「正确」为先，未做激进调优。

## 目录结构

所有公共模块都以 crate 名做前缀（`courierust_`），这样任何模块路径都不会与第三方 crate（如 `h2`、`http`、`bytes`、`grpc`、`tls`）冲突：

```
src/
├── courierust_http/        # HTTP/1.1 消息模型（请求/响应/头/URI/状态码）      [no_std]
├── courierust_hpack/       # HPACK：表驱动 Huffman + 静态/动态索引表           [no_std]
├── courierust_h2/          # HTTP/2 帧、SETTINGS、流状态机、流控、WUCS、PRIORITY_UPDATE [no_std]
├── courierust_quic/        # QUIC v1 包/帧编解码、varint、连接 ID、crypto 标签  [no_std]
├── courierust_h3/          # HTTP/3：QPACK 静态/动态表 + H3 帧/流角色         [no_std]
├── courierust_fingerprint/ # JA3 / JA4 / Chrome HTTP/2 指纹                    [no_std]
├── courierust_crypto/      # 自带 MD5 / SHA-256（指纹用）                      [no_std]
├── courierust_bytes/       # 字节缓冲（BytesMut）                              [no_std]
├── courierust_io/          # Read/Write trait（no_std 版）                     [no_std]
├── courierust_error/       # 统一错误类型
├── courierust_tls/         # TLS 1.2 + 1.3（RFC 5246/8446）：握手、记录层、X.509、HTTPS    [std]
├── courierust_pool/        # 工作窃取线程池                                    [std]
├── courierust_net/         # TCP → io trait 适配、轮询器、可选 stats 埋点      [std]
├── courierust_body/        # 流式响应体（channel）                             [std]
├── courierust_h1/          # HTTP/1.1 线上编解码                                [std]
├── courierust_client/      # h1 连接池 + h2 驱动                                [std]
├── courierust_server/      # 基于工作窃取池的服务器                             [std]
└── courierust_grpc/        # gRPC 帧 + 状态 + codec trait                       [std]
```

## 基准测试

`benches/` 是一个自包含基准套件（不依赖 criterion），每个用例都输出吞吐与完整延迟尾部分布——**P50 / P75 / P90 / P95 / P99**：

- HTTP/1.1 keep-alive，顺序与多 worker 并行；
- HTTP/2 多 worker 多路复用；
- HTTPS（TLS 1.2/1.3 + h2）经本仓库自带 TLS 栈的端到端；
- RFC 9218 优先级调度；
- 并发模型对比（空闲连接群 vs worker 池）与慢发送者群基准。

Workflow 还记录跨机 endpoint（含 TLS 与进程内限速场景）、reactor/连接/流证据（`STATS` 行）、TLS 验证证据（`TLSVERIFY` 行：`cert_verified` / `hostname_verified` / `negotiated_alpn` / `session_resumption`）和 `cargo-fuzz` parser 运行结果。生成的 `Github_Action_Benchmark.md` 会在 main 分支 push 后提交到仓库本身，不只存在于 Actions 摘要或 artifact 中。h2c 大 body 行（对同一 hyper h2 服务端的 1 MiB POST）受服务端 64 KiB 初始流控窗口（WINDOW_UPDATE 往返）限速，**不能用于比例论断**——即便换成 **async** reqwest 客户端，固定等待仍然存在（debug 下观测约 5–10 ms、release 约 3–8 ms，Courierust 约 2–4 ms），因此早前“blocking 客户端 harness 配置异常”的说法不成立。h2c 结果只适用于对应连接策略和负载，不能据此宣称全面领先。

**连接池语义两个客户端不同，不可混为一谈：** Courierust 的 `max_connections_per_host` 限制的是每个 authority 的*存活*连接数；reqwest 的 `pool_max_idle_per_host` 限制的是*空闲池化*连接数。两者设为相同的 N 只在顺序负载下等价——并发时 reqwest 可能建立超过 N 条存活连接。

**worker 数建议（由 `STATS` 行实测支持）：** HTTP/2 多路复用把所有流都放在一条连接、由一个 driver 线程串行处理。`max_connections_per_host = 1` 时吞吐在 4–8 worker 后随 worker 数**回退**：32 个 worker 争抢共享池锁与单一 driver 命令通道的速度超过 driver 的消化速度。`STATS` 行显示 `h2_connections=1` 且 `workers` 个并发流——这就是串行化点。每条 h2 连接建议 4–8 个客户端 worker，再往上应加连接而不是加 worker。

```bash
cargo bench --manifest-path benches/Cargo.toml --bench throughput
cargo bench --manifest-path benches/Cargo.toml --bench concurrency
cargo bench --manifest-path benches/Cargo.toml --bench interop
cargo bench --manifest-path benches/Cargo.toml --bench network
cargo fuzz run h2_frame --fuzz-dir fuzz -- -runs=10000
```

每条 `RESULT|...` 都带 `p50_us` … `p99_us`，报告脚本（`scripts/generate_benchmark_report.sh`）可生成分位表。这些是 loopback 测量；WAN / TLS / 真实 handler 的数字取决于你的部署——这正是套件要报完整尾部而非单一均值的原因。

## 互操作证据

`benches` 工作区还附带一套专门的**互操作验证**（`cargo bench --manifest-path benches/Cargo.toml --bench interop`）：在真实 socket 上让 Courierust 与主流 Rust HTTP 栈互通并断言语义正确（而非只测性能）：

- Courierust h1/h2c **客户端** → hyper h1/h2 **服务端**：路径回显、POST 回显、keep-alive 复用、h2 多路复用（并发不同路径不得串线）；
- hyper-util h1/h2c **客户端** → Courierust **服务端**，以及 reqwest（blocking，h1 与 h2c prior knowledge）→ Courierust **服务端**；
- 对真实 hyper 服务端的 1 MiB 请求/响应往返（双向流控窗口补充）与慢读 sanity 检查；
- **HTTP/3 自互操作**（H3 客户端与服务器均为本 crate 实现；工作区没有主流 H3 对端）：GET/POST 往返、池化连接复用、双向 256 KiB 请求/响应流控、单条 QUIC 连接上的并发流多路复用——作为 H3 路径的环回回归门（同样接入 `benchmark.yml`）。

该套件在每个 PR 的 CI（`benchmark.yml`）中运行，真实互操作回归会让流水线失败。主流 crate 仅是 bench 工作区的 dev 依赖；`courierust` 库本身保持零依赖。

`compare` bench 还跑一个 **HTTP/3 对比**，对端是业界标准的 **quinn + h3 crate**：两个客户端都复用同一条池化 QUIC 连接、面向同一个 Courierust H3 服务端，测量热路径每请求延迟（1 KiB / 64 KiB）。quinn 行目前报告 `not_available`：独立的 quinn/rustls QUIC/TLS 握手无法与 Courierust 服务端完成——这是真实的跨实现互操作缺口，如实上报而非造假。补齐它是开放项，与其它独立互操作工作并列。

## 测试

- 单元测试 253 个：覆盖 HPACK 全部 RFC 向量（C.2/C.3/C.4/C.6）、Huffman 编解码（含解码输出上限）、帧编解码、状态机、流控、WUCS 调度、JA3/JA4 公开记录比对、指纹解析、TLS 1.3 握手与 RFC 8448 密钥调度、TLS 1.2 握手（ECDHE-RSA/ECDSA AEAD 套件、PRF、RFC 5746 重协商回显、Ed25519 ServerKeyExchange 签名/验证）、X.25519/Ed25519/ECDSA/RSA 原语、DEFLATE/gzip 编解码（往返、CRC-32 向量、损坏拒绝、输出上限、与 Python zlib 输出交叉验证），以及轮询器 self-pipe（唤醒描述符）语义。
- 集成测试 63 个：真实 TCP 环回上的 h1/h2/HTTPS 请求往返、keep-alive 复用、chunked、重定向、h2 并发多路复用、流式响应、大体积流控往返、gRPC unary/服务端流/客户端流/双向流与错误状态/trailers/deadline 执行、gzip 往返、`grpc.health.v1.Health` `Check` + `Watch`、RFC 7540 §3.2 `h2c` Upgrade、**TLS 策略/加固**（信任拒绝、过期证书、不可信签发链、自签名但显式信任、主机名不匹配、ALPN 一致、TLS 1.2 与 TLS 1.3 分别用 RSA / P-384 / Ed25519 身份的完整往返、纯 TLS 1.3 客户端拒绝 TLS 1.2 服务器——绝不静默降级——与 RFC 8446 降级哨兵、握手中断失败、畸形 TLS 输入存活、`verify:false`）、并发证明（慢流不阻塞同连接其他流；大量空闲流按连接而非按流占 worker；空闲连接羊群不阻塞新请求；事件调度器回收 slow-loris 并执行 `max_connections`；服务端流式响应按短节奏冲刷；单条 h2 连接并发突发不饥饿），以及 **13 个 HTTP/3 集成测试**（QUIC v1 + TLS 1.3 真实 UDP 套接字、走公共 `Client`/`Server`）：GET/POST 往返、池化连接复用、双向 256 KiB 请求/响应流控、并发多路复用、每请求 deadline 执行、双向 key update，以及 H3 TLS 安全（不信任 / 过期 / 错误证书链 / 主机名不匹配证书均在握手阶段拒绝）。
- 加固测试 30 个：恶意帧输入（超长帧、畸形 SETTINGS/PING/WINDOW_UPDATE、流控窗口溢出、HPACK 头表与 Huffman 炸弹、截断/EOS Huffman、伪头顺序、`content-length` 不一致、非法 `transfer-encoding`/`connection` 系头、两端 `SETTINGS_MAX_CONCURRENT_STREAMS` 强制、`h2c` 存活检测：SETTINGS_TIMEOUT 与 keepalive 死对端检测）。

```bash
cargo test                 # 全部测试
cargo build --no-default-features   # 验证协议核心零警告编译
```

## 许可

Apache-2.0。
