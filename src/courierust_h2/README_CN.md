# courierust_h2

HTTP/2（RFC 9113）：帧、流状态机、流控、RFC 9218 优先级。`no_std`、零依赖，泛型于本 crate 的 `Read`/`Write` trait——所以**同一套 codec** 既能跑在 TCP 上，也能跑在 TLS 流上。

没错，又一个 HTTP/2 实现。区别是：这个不包 `h2`。

## 里面有什么

- **完整帧编解码**——DATA / HEADERS / PRIORITY / RST_STREAM / SETTINGS / PUSH_PROMISE / PING / GOAWAY / WINDOW_UPDATE / CONTINUATION，外加 RFC 9218 的 `PRIORITY_UPDATE`（类型 `0x10`）。
- **严格按 §5.1 的流状态机**。非法迁移直接 `PROTOCOL_ERROR`。没有"差不多"的状态。
- **畸形消息是流级错误**（RFC 9113 §8.1.1）：非法字段块——连接专用字段（§8.2.2）、常规字段之后的伪首部或对该消息类型未定义的伪首部（§8.3）、携带伪首部或分帧字段的 trailer——会用 `PROTOCOL_ERROR` 复位*那一条流*，连接与其它流保持可用，而不是让一个坏请求拖垮整个多路复用。两个值得知道的推论：RFC 8441 扩展 CONNECT（`:protocol`）的拒绝方式正是 RFC 8441 §3 为「对端从未声明 `SETTINGS_ENABLE_CONNECT_PROTOCOL`」定义的；而在 h2 连接上发 HTTP/1.1 式的 WebSocket `Upgrade`，得到的是被复位的流，而不是一个被交给 handler 的普通请求。连接级错误只留给真会破坏连接同步的情况：HPACK 解码失败（`COMPRESSION_ERROR`）、帧层违规，以及相互冲突的分帧字段（请求走私，CWE-444）。
- **两级流控**（连接级 + 每流），窗口按帧推进，双向都查溢出。
- **RFC 9218 优先级**——`Priority` 头 / `PRIORITY_UPDATE` 解析，背后是 WUCS 调度器（`priority.rs`）。每帧 O(1)，可证明反饥饿；设计稿在 `blogs/01-wucs-scheduler.md`。
- **BCR（批量信用回流）**——已收数据信用攒批归还，而不是每帧一个 `WINDOW_UPDATE`。控制帧降一个数量级；窗口永远不会坍缩到 0，发送方不会卡在 RTT 上。见 `blogs/02-bcr-flow-control.md`。

## 架构

`connection.rs` 是有状态的心脏——它拥有流表、两级流控窗口、WUCS 调度器和编解码器的接线，并产出一条有序事件流供传输层消费。其余是零件：

| 文件 | 角色 |
|---|---|
| `frame.rs` | 每种帧的线上编解码 |
| `stream.rs` | 每流状态 + 发送/接收窗口 |
| `flow.rs` | `FlowWindow`，i64 饱和运算 |
| `settings.rs` | SETTINGS 跟踪与 RFC 规定的重配规则 |
| `priority.rs` | RFC 9218 解析 + WUCS 调度器 |
| `error.rs` | HTTP/2 错误码 → crate 统一 `Error` |

连接泛型于 `Read`/`Write`——这正是阻塞服务器、h2 客户端 driver 线程、（经 TLS 记录层）HTTPS 三处复用同一份实现的原因。

## 加固

这层把对端每个字节都当恶意：HPACK 炸弹（整数溢出、头列表上限、动态表大小、Huffman EOS/padding）、流控窗口溢出（`FLOW_CONTROL_ERROR`）、无 body 消息上的 DATA、流结束时的 `content-length` 不匹配、idle 流上的 RST、`SETTINGS_TIMEOUT`、keepalive 死对端检测。30 个加固测试就是干这个的。

## 用法

通常你不直接碰它——`courierust_client` 和 `courierust_server` 会驱动它。但如果你想要一个跑在自己传输上的裸 h2 codec，`connection::Connection` 是公开的，测试很全。
