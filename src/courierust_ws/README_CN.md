# courierust_ws

一套完整的 RFC 6455 WebSocket 实现 —— 组帧、掩码、UTF-8 校验、握手、关闭握手、分片重组，以及 RFC 7692 `permessage-deflate` —— **零第三方依赖**，并且服务端/客户端接入复用本 crate 自己的 TCP/TLS 栈。

除真正需要 socket 的部分（掩码密钥的熵源、`SharedSink`、客户端）之外，全部是 `no_std + alloc`。协议核心除调用方收到的消息负载外，不会按帧分配内存。

```
frame.rs      线上格式：帧头、操作码、掩码、输出端（StreamSink / SharedSink / VecSink）
utf8.rs       增量 UTF-8 校验，不复制消息
handshake.rs  HTTP 升级：key 校验、Origin 策略、扩展协商、子协议选择
writer.rs     出站组帧 + 压缩决策，每帧一次加锁
session.rs    双向状态机：读、写、限额、关闭
```

## 为什么快

在同一台机器、同一进程、同一编译配置下与 `tungstenite 0.30` 对比（方法论与完整表格见 [`benches/WS_BENCHMARK.md`](../../benches/WS_BENCHMARK.md)）：

| 操作（64 字节） | courierust | tungstenite | |
|---|---:|---:|---|
| 编码（服务端，不掩码） | 5.7 ns | 12.9 ns | 快 2.3 倍 |
| 编码（客户端，掩码） | 15.2 ns | 40.0 ns | 快 2.6 倍 |
| 原地掩码 | 2.4 ns | — | 25 GB/s |

| 操作（256 KiB） | courierust | tungstenite | |
|---|---:|---:|---|
| 编码（客户端，掩码） | 9.5 µs | 90-99 µs | 约 10 倍 |
| 单向推送（服务端 → 客户端） | 74 µs | 73 µs | 持平 |

四个关键决策贡献了绝大部分收益：

1. **16 字节通道掩码。** 以 4 字节为周期循环异或无法被向量化，因为密钥随 `i & 3` 变化。而 16 是 4 的倍数，**每个 16 字节通道的相位都相同**：正文退化为 `lane ^= 常量`（一个预计算的 `u128`），编译器直接用宽 SIMD 处理，尾部用同样的思路配 `u32`。仅这一条就把掩码从 23 GB/s 提到 36 GB/s。
2. **读路径零拷贝。** 帧头直接从读缓冲区解析（`FrameHeader::header_len_hint` 连复制都省掉），超过 8 KiB 的负载余量**直接读入消息缓冲区**，不经过缓冲读取器的中间复制；掩码在数据到达时原地完成，与读取融合。
3. **可复用的 DEFLATE 上下文。** `MatchFinder`（128 KiB 哈希表 + 链式表）保存在 `Deflater` 中，重置代价与消息长度成正比而不是与表大小成正比。天真的按消息新建上下文在小消息上仅 `memset` 就要约 40 µs，比压缩本身还贵。
4. **小帧一次写系统调用。** ≤ 64 KiB 的帧合并进暂存缓冲区后一次写出；更大的帧在不掩码时直接从调用方缓冲区写出，掩码时按最大 1 MiB 的分块处理。小消息延迟真正关心的是"几个系统调用"。

## 安全设计

- **掩码方向双向强制。** 服务端收到未掩码的客户端帧直接断开；客户端收到被掩码的服务端帧直接断开（§5.1）。搞反方向正是中间缓存被投毒的原因。
- **默认校验 Origin。** 默认 `OriginPolicy::SameOrigin`：其他站点上的页面无法打开带凭证的 WebSocket，因为浏览器会连同会话 Cookie 一起发起升级。非浏览器客户端用 `NoOrigin`，白名单用 `List`，明确放弃校验才用 `Any`。
- **`X-Forwarded-*` 只信任你指定的代理。** `trusted_proxies: Vec<IpNet>` 决定何时允许 `X-Forwarded-For` / `X-Forwarded-Proto` 覆盖对端地址；来自非可信来源的头部被忽略，客户端无法伪造自己的 IP，也无法谎称链路是 TLS。
- **严格握手校验。** 恰好一个规范 base64 长度的 `Sec-WebSocket-Key`、`Sec-WebSocket-Version: 13`、`Connection: Upgrade` 按 token 列表匹配、最短长度编码、控制帧不可分片且不超过 125 字节、RSV 位需协商后才允许、关闭码按方向合法性校验。
- **一切都有上限。** `max_frame`、`max_message`、`max_fragments`、`max_send_queue`：对端无法把"声明的大小"变成内存占用；`permessage-deflate` 解压同样受消息上限约束（zip bomb 得到的是 1009，而不是 OOM，且有测试）。
- **关闭握手是强制约束，不是建议。** "Close 帧之后不得再发任何帧"（RFC 6455 §5.5.1）由一个**连接级共享标志**保证：与应用线程推送竞态的发送会被拒绝（`ErrorKind::Canceled`），而不是写出一个对端有权判定为协议错误的数据帧。同一 socket 上的会话写入器与应用写入器看到的是同一个标志。
- **HTTP/1.1 必须携带 `Host`**（RFC 9112 §3.2），两条服务端驱动路径都在任何 handler 或 WebSocket 策略之前检查：可能被两跳解释成不同 authority 的请求一律以 `400` 拒绝而不是路由。缺失、重复或为空的 `Host` 都失败关闭；`HTTP/1.0` 允许省略。
- **传输故障不等于协议错误。** 只有对端的协议违规与超限消息才会回送 Close 帧（1002/1007/1009）；socket 断开以 `code = None, clean = false` 报告给应用，而不是粉饰成对端的错。
- **限额在缓冲之前生效。** 超限帧在写入缓冲区之前就以 1009 失败；非法文本消息在出错的偏移处（1007）被拒绝，原因字符串按 UTF-8 边界截断。
- **掩码密钥来自 CSPRNG。** 用平台熵播种的 ChaCha20 流，每帧一个新密钥 —— 不是计数器，也不是时间戳。

## 部署：在反向代理处终结 TLS

推荐的生产形态是在前面放一个反向代理，由它做 TLS（即 `wss://`），需要的话还可以为其他流量提供 HTTP/2 或 HTTP/3：

```nginx
# nginx
location /ws/ {
    proxy_pass http://127.0.0.1:8080;
    proxy_http_version 1.1;

    # 升级握手本身
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";

    # 真实客户端地址：只应来自你自己的代理
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;

    # 不要缓冲帧：会毁掉延迟，甚至阻塞数据流
    proxy_buffering off;

    # WebSocket 在两条消息之间天然是空闲的；让它保持存活的是
    # 应用层 keepalive（ping_interval），所以代理超时必须更长。
    proxy_read_timeout 3600s;
    proxy_send_timeout 3600s;
}
```

Traefik：

```yaml
http:
  routers:
    ws:
      rule: "Host(`example.com`) && PathPrefix(`/ws`)"
      service: app
      entryPoints: [websecure]
      tls: {}
```

然后让服务端配置与之匹配：

```rust
let ws = WsConfig {
    origin: OriginPolicy::List(vec!["https://app.example.com".into()]),
    trusted_proxies: vec![IpNet::parse("127.0.0.1/32")?, IpNet::parse("10.0.0.0/8")?],
    ..Default::default()
};
```

两条最容易出错的规则：

- **代理的读取超时必须长于 `ping_interval`。** 关闭空闲 WebSocket 的代理会掐掉本来健康的连接；Ping/Pong 保活正是为了让连接在消息间隙看起来仍然活着。
- **没有 `trusted_proxies` 时绝不信任 `X-Forwarded-For`。** 未设置时 `client_ip` 是 socket 的对端地址（即代理），这是安全的；设置之后，只有来自列表内网段的请求才能覆盖它。

## 诚实说明

- **未实现 RFC 8441（WebSocket over HTTP/2）。** 客户端在 ALPN 中**只**提供 `http/1.1`——即使 `ClientConfig::http2` 为 `true`——且如果连接最终落在 h2 上，会在读到任何一帧之前拒绝。服务器侧：在**已建立的** h2 连接上尝试 WebSocket 属于畸形消息，按 RFC 9113 §8.1.1 作为**流级错误（`PROTOCOL_ERROR`）** 拒绝，两种形式都如此：RFC 8441 的扩展 CONNECT（`:method = CONNECT` 配 `:protocol = websocket`，在本栈里是未定义伪首部——正是 RFC 8441 §3 为「对端从未声明 `SETTINGS_ENABLE_CONNECT_PROTOCOL`」定义的拒绝方式），以及 HTTP/1.1 式的 `Upgrade: websocket` / `Connection: Upgrade`（连接专用字段，§8.2.2）。连接与其它流保持可用。绝不会出现的两种失败形态值得点名：对一个不可能成为 WebSocket 的请求回 `200`，以及建立一条看似成功却不承载任何帧的连接。WebSocket 请用 HTTP/1.1 承载，与绝大多数场景一致。
- **`permessage-deflate` 对每条消息独立压缩。** 我们的编码器从不使用上下文接管（context takeover）——这永远合法（解码器的窗口是超集），并且彻底消除了"某条消息的明文泄漏进另一条消息"这类缺陷。代价是对大量微小重复消息的压缩率有上限损失，收益是服务端不必为每条连接保留 32 KiB 滑动窗口，可以承载数千连接。
- **`SO_RCVTIMEO` 只在空闲等待时开启。** Windows 会对 socket 的每一次阻塞操作计费，包括写操作：实测 256 KiB 推送循环在发送方设置了截止时间后慢约 2 倍，两端都设置则慢约 10 倍。因此阻塞服务端仅在等待下一帧时开启截止时间，处理消息期间清除（`ping_interval` 仍是存活检测机制）。**客户端** 会按 `ClientConfig::read_timeout` 在整个连接期间保留截止时间——这对交互式流量是合理的默认值，但在 Windows 上对 256 KiB 批量传输约多花一倍时间；批量传输的客户端应设 `read_timeout: None` 并用应用层存活检测，与服务端一致。两项结论的实测数据见 [`benches/WS_BENCHMARK.md`](../../benches/WS_BENCHMARK.md)。
- **不要在 reactor 回调里做批量推送。** 事件驱动驱动中，服务回调运行在 reactor 工作线程上；在 `on_message` 里循环推送成千上万条消息会阻塞本该排空发送队列的 reactor，队列上限最终会关闭连接。扇出的正确姿势是其他线程使用 `WsConn::sender()`（`WsSender`）排队并唤醒。
- **URL 解析只覆盖 `ws://` / `wss://`。** `normalise_url` 只做协议名到 `http`/`https` 的映射，其他形式一律拒绝，而不是"理解一半"。

## 用法

服务端：

```rust
use courierust::courierust_server::ws::{WsConn, WsData, WsService, WsUpgradeReply};
use std::sync::Arc;

struct Echo;

impl WsService for Echo {
    fn on_message(&self, conn: &mut WsConn, msg: WsData) {
        match msg {
            WsData::Text(t) => { let _ = conn.send_text(&t); }
            WsData::Binary(b) => { let _ = conn.send_binary(&b); }
        }
    }
    fn on_close(&self, conn: &mut WsConn, code: Option<u16>, clean: bool) {
        eprintln!("closed: code={code:?} clean={clean} path={}", conn.path());
    }
}

struct App;
impl courierust::courierust_server::Handler for App {
    fn handle(&self, _req: courierust::courierust_http::request::Request<
        courierust::courierust_body::Body>) -> courierust::courierust_http::response::Response<
        courierust::courierust_body::Body> {
        courierust::courierust_http::response::Response::text("hello")
    }
    fn websocket(&self, req: &courierust::courierust_http::request::Request<
        courierust::courierust_body::Body>) -> WsUpgradeReply {
        if req.path == "/echo" { WsUpgradeReply::Accept(Arc::new(Echo)) }
        else { WsUpgradeReply::Pass }   // 交给 HTTP 处理器返回 404
    }
}
```

客户端：

```rust
use courierust::courierust_client::ClientConfig;
use courierust::courierust_client::ws::WebSocket;

let mut ws = WebSocket::connect("wss://example.com/ws", &ClientConfig::default())?;
ws.send_text("hello")?;
for msg in [ws.read_message()?] {
    println!("{msg:?}");
}
ws.close(1000, "done")?;
```

可运行版本见 [`examples/ws_echo.rs`](../../examples/ws_echo.rs) 与 [`examples/ws_client.rs`](../../examples/ws_client.rs)；[`tests/ws.rs`](../../tests/ws.rs) 中的 34 个端到端测试针对真实 socket 验证线上协议，包括跨驱动推送、Origin 拒绝、TLS 上的 `wss` 以及各类错误码。

## 接下来看哪里

- 中英文教程：Wiki —— [WebSocket 使用指南](https://github.com/blueokanna/Courierust/wiki/WebSocket-%E4%BD%BF%E7%94%A8%E6%8C%87%E5%8D%97) / [WebSockets](https://github.com/blueokanna/Courierust/wiki/WebSockets)。
- 可直接运行的示例：`cargo run --example ws_echo`（同进程内服务器 + 客户端）、`cargo run --example ws_client`（带生产级配置的客户端，可连任意端点）。
- 实测数据与诚实的弱点：[`benches/WS_BENCHMARK.md`](../../benches/WS_BENCHMARK.md)。
- 服务端/客户端接入细节：[`../courierust_server/README_CN.md`](../courierust_server/README_CN.md)（`Handler::websocket` 钩子与 reactor）与 [`../courierust_client/README_CN.md`](../courierust_client/README_CN.md)。
