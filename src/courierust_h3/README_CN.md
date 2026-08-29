# courierust_h3

HTTP/3（RFC 9114）：帧、流角色、SETTINGS、QPACK（RFC 9204）字段行压缩。codec 部分 `no_std`；`std` 下，UDP reactor + QUIC-TLS 适配器把 HTTP/3 路径端到端跑起来，底下是内置的 QUIC v1 codec 和 TLS 1.3。

## 里面有什么

- **`frame.rs`**——HTTP/3 帧类型、SETTINGS 标识符、单向流角色（control / push / QPACK encoder / QPACK decoder）。
- **`qpack.rs`**——完整 QPACK codec：**99 项静态表**、前缀整数、Huffman 字符串、每一种字段行表示（T 位、relative/post-base 索引）、动态表、编码器/解码器指令流。对照 RFC 9204 附录 B.1–B.4 验证。
- **`runtime.rs`**（std）——把它们接起来的 UDP reactor：QUIC v1 包保护、ALPN `h3` 的 TLS 1.3、control/QPACK 流、请求流、响应 trailer、GOAWAY 校验、重传、严格流重组。

## QPACK 的坑

QPACK 的静态表是 **0 索引**的，跟 HPACK 的 1 索引不一样。这里错一位，每条 indexed 字段行都会解到错误的头上。这正是那种"冒烟测试能过、生产环境炸掉"的 off-by-one——附录向量就是用来抓它的。

## 诚实的边界

传输长尾已实现并有测试覆盖：完整 PTO/时间阈值丢包恢复、动态本地流控 credit（MAX_DATA / MAX_STREAM_DATA / MAX_STREAMS）、连接迁移与路径验证、stateless reset（生成与校验）、带单次保护的双向自动 key update、QPACK blocked-stream ack（解码器流上的 Section Acknowledgment / Stream Cancellation / Insert Count Increment）。刻意不做：0-RTT / early data（不承担重放防护的复杂度），以及独立实现互操作（quinn+h3 的握手互操作缺口在基准套件里如实上报，而不是造假）。这两项是把它当"互联网就绪"前的剩余事项。

## Reactor 与延迟模型

reactor 是 poller 驱动的事件循环（一个 UDP socket、一根 wake pipe、有界 drain），不是固定周期扫描。两条规则保证长尾是诚实的：

1. **每个 ack-eliciting 包立即回 ACK。** burst 的第一个包标记为"已到期"并随批次 flush，其余包合并进这同一个 ACK；只有 straggler 或重复包才打开一个有界窗口。把每个 ACK 都压在固定窗口后面正是环回长尾的根源——以前每个 cwnd-limited round 要等满 `ack_delay()` *外加* reactor 的 poll tick。
2. **poll timeout 是绝对 deadline，不是节拍。** reactor 睡到最早的协议 deadline（待发 ACK 批次、loss/PTO 定时器、路径校验、请求超时），绝不"睡 5 ms 再看"。数据报仍然即时唤醒它；deadline 只约束纯定时器事件的等待上界。

`COURIERUST_H3_ACK_DELAY_MS` / `COURIERUST_H3_MIN_ACK_DELAY_MS` 仍控制 straggler 窗口，`COURIERUST_H3_POLL_*` 约束兜底 park，`COURIERUST_H3_CWND` 控制初始拥塞窗口。`courierust_net::Stats` 里的 `h3_ack_deferred` / `h3_credit_stalls` 计数器可以证明到底是批次窗口还是拥塞窗口在给一条流限速。

## 用法

公开的 `Client`/`Server`（`courierust_client` / `courierust_server`）会把 `http3://`（以及 ALPN `h3` 的 `https://`）路由进这个 runtime。`examples/h3.rs` 是可跑的端到端示例：冷连接 vs 池化复用、大响应流控、并发多路复用、证书拒绝。
