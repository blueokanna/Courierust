# H3 的"5 毫秒量子"：一个写在注释里、却从没真正生效的快速路径

## 这次的故事

H1 的 5ms P99 尖峰（`03-self-pipe-event-scheduler.md`）解决了之后，我又在 HTTP/3 上撞见了同一个量级的鬼：**P50 很漂亮，但总有一部分请求被固定拖进 5–7 ms 的区间。**

同一个 Courierust H3 服务端，换 Quinn + h3 客户端来访问：1 KiB 的 P99 只有 286 µs，64 KiB 也只有 1.24 ms。**服务端没问题。** 问题出在 Courierust 自己的 H3 客户端路径上——更准确地说，是"我方收包→回 ACK→对端继续发"这条链上。

先上证据（h3 bench，release，loopback，安静机器）：

| 用例 | 修复前 | 修复后 |
| --- | --- | --- |
| `h3_sequential` p50 / max | 348 µs / 8.4 ms | 115 µs / 0.21 ms |
| `h3_parallel`×4 p50 / p99 | 887 µs / 6.0 ms | 181 µs / 0.35 ms |
| 64 KiB 上传 p50 | 9.2 ms | 1.15 ms |
| 64 KiB 下载 p99 | — | 0.74 ms（quinn 1.24 ms） |

台阶消失了。而且这次不是"盲调参数碰对了"，是把一个**写了注释但从来没生效的快速路径**真正实现了。

---

## 先理解 QUIC 的 ACK 是怎么被"压"住的

QUIC 的发送受拥塞窗口（cwnd）约束：发到窗口满了，就得等对端的 ACK 把窗口腾出来。所以**一次大 body 传输 = 好几轮"发一窗 → 等 ACK → 再发"**。每一轮多长，取决于 ACK 回来的速度。

RFC 9002 §6.2.2 给了个交互式快速路径：**burst 的第一个 ack-eliciting 包应该立即回 ACK**，同一批的后续包合并进这一个 ACK。这样流控轮的节奏 = 对端的 ACK 延迟，而不是我们自己的批量窗口。

我的代码里确实写着这个意图。看 `QuicTransport::ack()`：

```rust
if !space.ack_pending {
    // RFC 9002 §6.2.2 interactive fast path: acknowledge the first
    // ack-eliciting packet of a batch immediately (deadline None).
    space.ack_pending = true;
    space.ack_deadline = None;
}
```

注释说得清清楚楚。但它是**死代码**。为什么？因为 `open()`——每个收包都会经过的唯一入口——在那之前已经抢先做了：

```rust
if ack_eliciting {
    space.ack_pending = true;
    space.ack_deadline = Some(Instant::now() + ack_delay());
}
```

`ack_pending` 已经被置成 `true`，`ack()` 走进 `if !ack_pending` 永远为假，只能落到 `else if` 分支再 arm 一次。快速路径那个分支，一次都没跑过。

于是每个 ACK 都被压在 `ack_delay()`（默认 2 ms，环回上自适应到 ~0.6 ms）后面。这本身也就几百微秒，还没到 5 ms。**真正要命的叠加是第二层：**

## 第二层：poll timeout 是固定节拍，不是 deadline

客户端 driver 和服务器 reactor 的 poll timeout 是写死的：

```rust
let wait_ms = if conn.has_work() { client_busy_poll_ms() } else { ... };
// client_busy_poll_ms() = 5
```

`earliest_deadline()` 只包含请求超时，**不含 ACK 批次 deadline、loss/PTO 定时器、路径校验**。于是时序变成：

1. 我方收到一窗数据，ACK 被 arm 在 `now + 600 µs`；
2. `flush_ack` 一看"还没到期"，返回；
3. 进入 `poll(5 ms)`——**没有任何东西会在 600 µs 时唤醒它**；
4. 5 ms 后 poll 返回，ACK 才真正发出去。

对端等这个 ACK 等了 5 ms。下一轮又是 5 ms。环回上一来一回，64 KiB 的请求就变成了"一次 5 ms 台阶、偶尔两次"。**这就是那个"时间量子指纹"**——不是随机抖动，是固定节拍本身。

H1 的教训在这里复刻了一遍：控制消息（当年是自唤醒管道，这里是 ACK/credit）不能等下一个固定 poll tick。

---

## 修复：政策收拢到一个 choke point，deadline 折叠进 poll

两处改动，没有魔法。

**第一处：把交互式快速路径真正实现进 `open()`。**

`open()` 是客户端和服务端共用的收包唯一入口，ACK 政策放这里，就不会再有"注释写了一套、代码跑另一套"的分裂：

```rust
if ack_eliciting {
    if !space.ack_pending {
        space.ack_pending = true;
        space.ack_deadline = None;      // burst 第一个包：立即回
    } else if let Some(deadline) = space.ack_deadline {
        if deadline > Instant::now() {
            space.ack_deadline = Some(Instant::now() + adaptive_delay);
        }
    }
}
```

第一个包标记"立即"，同一 burst 的后续包保持 `None` 合并进这一个 ACK；只有 straggler（窗口已经 flush 之后才来的）或重复包才 arm 一个有界窗口。死代码 `ack()` 整个删掉，政策单一化。

**第二处：poll timeout 折叠协议 deadline。**

新增 `QuicTransport::earliest_deadline()`——取待发 ACK 批次 deadline、路径校验超时、以及最早 in-flight ack-eliciting 包的 loss/PTO 定时器的最小值。客户端 driver 和服务器 reactor 都把它并进 `wait_ms`：

```rust
if let Some(deadline) = conn.transport.earliest_deadline() {
    wait_ms = wait_ms.min((deadline - now).as_millis());
}
```

poll 现在睡到**下一个协议事件真正发生的时间**，而不是"睡 5 ms 再看"。数据报仍然即时唤醒 poll，deadline 只约束纯定时器事件的等待上界。

**顺手的一件小事：**

`Stats` 加了 `h3_ack_deferred`（ACK 被批次窗口推迟的次数）和 `h3_credit_stalls`（cwnd 满导致的发送停顿次数）。**先测量再调参**——这两个计数器能直接回答"是批次窗口在限速还是拥塞窗口在限速"。

（一开始我还试着把 UDP socket 缓冲提到 1 MiB——quinn 就这尺寸。实测环回默认缓冲是 64 KiB，64 KiB 的 burst 本来就放得下，收益几乎为零；而且裸 `setsockopt` FFI 破坏了这个 crate "全程无 unsafe" 的承诺，所以整个回退了。）

---

## 一个调试陷阱

`COURIERUST_H3_TRACE` 的逐包 `eprintln!` 在 Windows 上每行几十到上百微秒。开着它去测 timing，会看到"发送花了 4.4 ms"这种假象——把 27 个包的发送间隔撑出一堆 2 ms 的簇。**别开着逐包 trace 测延迟。** 我把每请求的阶段分解（`total_us|send_us|wait_headers_us|recv_body_us`）拆成独立的 `COURIERUST_H3_TRACE_MS` 开关，不带逐包开销，才能看到真实的 `send_us` 构成。

## 收尾

- 349 个测试全绿（256 单元 + 50 集成 + 30 加固 + 12 H3 + 1 key-update），clippy / no_std / fmt 干净。
- 诊断计数器留在生产路径上，成本只是几个无竞争的原子加。
- 长尾不是玄学：**凡是"消息到达但 poll 没被立即打断"的地方，都要么自唤醒、要么把 deadline 折叠进 poll timeout。** H1 用 self-pipe 解决了一次，H3 这次是 ACK 政策 + deadline 折叠。下回再看到固定的毫秒台阶，先找"谁在等下一个固定 tick"。
