# 一个 5ms 的 P99 尖峰，逼我写了个"烧水壶哨子"

## 先说这个故事的开头

Courierust 的服务器刚能跑起来的时候，我跑基准测试，结果怎么都消不掉一个现象：

**每次请求的延迟，P99 永远有大概 5ms 的尖峰。**

P50（一半请求）是 100µs 左右，P99 却稳定地飙到 5ms。这不是偶发，是**每次都有**。看起来就像每个请求都被什么东西"卡"了一下。

我当时一度怀疑是调度问题、是锁竞争、是 GC……折腾了很久，最后才找到真凶。这个真凶，逼出了一个挺有意思的设计——一个自制的"烧水壶哨子"。

先把背景讲清楚。

---

## 服务器并发模型的演进：用一家餐厅来想

假设你开了一家餐厅，要接待很多客人（网络连接）。怎么安排服务员（处理线程）？历史上大概有三代做法。

### 第一代：一连接一服务员

每个客人进门，你就派一个专属服务员全程跟着。

- 好处：简单，一个服务员只管一个客人，不会搞混；
- 坏处：**客人吃完饭坐着不走呢？** 1000 个客人坐在那里刷手机（这就是 keep-alive 连接、SSE 长连接），你就得养 1000 个服务员站桩。餐厅破产。

这就是"一连接一线程"模型。10 万条空闲连接 = 10 万个线程，光线程栈内存就能吃几个 GB。

### 第二代：服务员共享（工作窃取池）

服务员不再专属，改成"谁有空谁接客"的共享池。

- 好处：服务员数量可控了，多核也能用上；
- 坏处：**还是那句话——客人坐着不走，服务员也得在旁边陪着。** 1000 个"半截话没说完整"的客人（Slowloris），照样把服务员全占满，新客人进门没人理。

### 第三代（我们的）：客人按铃，服务员才来

关键洞察：**客人大多数时间并不需要服务员，他们只是"待在座位上"。**

所以新一代做法是：

- 客人坐下（连接建立）后，**不占任何服务员**，自己待着；
- 客人需要服务时（数据到达），**按铃**（socket 就绪）；
- 服务员听到铃响，才过来服务；
- 服务完，客人回座位，服务员去忙别人。

这就像餐厅给每桌装了个呼叫铃，客人按铃才有服务员来，不按铃服务员就去忙别的桌。

用技术话说就是：**空闲连接挂在轮询器（poll）上，就绪了才交给 worker 处理。** 一个 worker 能同时"陪"几千个待着的客人，因为大部分时间它只是在睡觉，等铃响。

```mermaid
flowchart TB
    A[accept 线程<br/>只负责接客，绝不阻塞] -->|"新连接 + 按一下铃"| BELL
    BELL["self-pipe（烧水壶哨子）"] -->|"读端注册进 poller"| EL[前台：事件循环<br/>持有 poller + 分类器]
    EL -->|"poll（select/poll）等铃响"| P[铃响的客人集合]
    P -->|"分类：TLS/h2/h1"| H1[H1 客人 → EventConn]
    P -->|"TLS / h2"| POOL[服务员池]
    H1 -->|"按 16 人一批叫服务员"| EW[服务员 ×N]
    EW -->|"服务完 → 重新登记 + 按铃"| BELL
    EL -->|"超时未动 → 请走"| REAP[慢客人回收]
```

---

## 死结：前台每 5 分钟才看一次铃

架构想清楚了，代码也写出来了，然后那个 **5ms 的 P99 尖峰**就来了。

我把架构再细化一层，你就明白坑在哪了。

事件循环（前台）的经典写法是这样的：

```text
loop {
    poll(5ms)          // 前台盯着铃，最多盯 5ms
    // 处理就绪的客人
    // 处理控制消息（新客人、服务员登记……）
}
```

注意：**服务员和前台之间，是靠一个消息队列（channel）通信的，而前台的眼睛（poll）只盯着客人的铃，不盯着消息队列。**

问题来了：服务员服务完一个客人，想把客人放回座位、并通知前台"这位客人可以继续接待了"——它把消息丢进队列，然后呢？

**前台要等当前这轮 poll 结束才看队列。**

而 poll 最多要等 5ms。所以：

> **每个 keep-alive 请求，服务员处理完、通知前台、前台重新把客人挂回去——这一整个交接，都要等一个完整的 5ms poll 超时。**

这就是 P99 5ms 尖峰的来源。不是锁，不是调度，就是**前台每 5ms 才睁一次眼，而每次交接都必须等它睁眼**。

用生活中的话说：你给前台写了个纸条"3 号桌可以上菜了"，扔进信箱，但前台**每 5 分钟才开一次信箱**——那 3 号桌就得干等 5 分钟。

### 为什么不能把 poll 超时设成 0？

你可能会想：那把 5ms 改成 0 不就行了？让前台永远睁着眼。

**不行。** poll 超时 = 0 就是忙轮询——前台每时每刻都在扫视所有客人，CPU 直接烧满一个核，而且"没客人按铃时前台该干嘛"这个问题又回来了（它还是得干等，只是干等的姿势变成了空转）。

我们要的是：**没人的时候前台能踏实睡觉，有人的时候前台能立刻醒来。** 既要省电，又要秒回。

---

## 解法：给自己做个"烧水壶哨子"

这个问题的经典解法，在 Unix 世界里有个很老的名字，叫 **self-pipe trick**（自管道技巧），Windows 上也有对应的做法。通俗点讲，就是：

> **给前台装一个哨子。任何要通知前台的人，不必等前台睁眼，直接吹哨子。哨子一响，前台立刻醒来。**

具体实现很朴素——一对回环 TCP socket（自己连自己的 loopback 连接）：

```rust
/// 创建一对回环 socket 作为 self-pipe（烧水壶哨子）。
/// Windows 没有原生 socketpair，回环对是可移植的等价物。
pub(crate) fn wakeup_pair() -> std::io::Result<(TcpStream, TcpStream)> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let writer = TcpStream::connect(listener.local_addr()?)?;
    let (reader, _) = listener.accept()?;

    // 关键中的关键：关掉 Nagle！
    // 哨子就吹一声（1 个字节），必须立刻到达前台耳朵里。
    // Nagle 会把这个字节攒在缓冲区里等更多数据——
    // 那哨子就不响了，等于又回到"等 5 分钟"的老路。
    reader.set_nonblocking(true)?;
    writer.set_nonblocking(true)?;
    let _ = reader.set_nodelay(true);
    let _ = writer.set_nodelay(true);
    Ok((reader, writer))
}

/// 吹哨子：写一个字节。尽力而为，写失败只损失一次优化，绝不损失正确性。
pub(crate) fn wake_nudge(w: &TcpStream) {
    let mut s: &TcpStream = w;
    let _ = std::io::Write::write(&mut s, &[1]);
}

/// 把哨声排空，防止哨子"卡住"反复假响。
pub(crate) fn drain_wake(r: &TcpStream) {
    let mut buf = [0u8; 64];
    loop {
        let mut s: &TcpStream = r;
        match std::io::Read::read(&mut s, &mut buf) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
    }
}
```

然后，**把这个哨子的"耳朵"（reader 端）也注册进前台的眼睛（poller）里**：

```rust
// 事件循环主循环（节选）
loop {
    // 1. 先睁眼看看信箱里有没有纸条（排空控制消息）
    let mut drained = 0;
    loop {
        match msg_rx.try_recv() {
            Ok(msg) => { drained += 1; handle_msg(msg, ...); }
            Err(TryRecvError::Empty) => break,
            Err(TryRecvError::Disconnected) => return,
        }
    }

    // 2. 一个客人都没有时，直接睡觉等纸条（避免空转）
    if poller.is_empty() {
        match msg_rx.recv() {
            Ok(msg) => handle_msg(msg, ...),
            Err(_) => return,
        }
        continue;
    }

    // 3. 睡觉，但耳朵里塞着哨子（poll 时一起监视 wake 描述符）
    let ready = match poller.wait(wait_ms, Some(wake_fd)) {
        Ok(r) => r,
        Err(_) => continue,
    };

    // 4. 哨子响了 = 有纸条在信箱里 → 立刻醒，先排空哨声，再处理纸条
    if ready.contains(&WAKE_ID) {
        drain_wake(&wake_reader);
        loop {
            match msg_rx.try_recv() {
                Ok(msg) => handle_msg(msg, ...),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => return,
            }
        }
    }

    // 5. 分类并按批派发就绪客人……
    // 6. 回收超时没动静的客人……
}
```

这一步做完，整个系统的性质就变了：

- **客人按铃**（数据到达）→ socket 就绪 → poll 立刻返回（这是本来就有的）；
- **服务员吹哨**（要登记客人）→ 哨子字节到达 → **poll 立刻返回**；
- **接客线程吹哨**（来了新客人）→ 哨子字节到达 → **poll 立刻返回**。

**poll 超时现在只在一个场景起作用：真的什么都没有发生。** 它彻底退出了请求延迟路径。那个 5ms 的 P99 尖峰，就这么消失了。

这就回到了题目：**你不必每 5 分钟去厨房看一眼水开没开（轮询），水开了哨子会响（事件驱动）——但前提是，你得让哨子能真正吵醒你。** self-pipe 就是那个"能吵醒你的哨子"。

---

## 顺手做的几件小事（每个都踩过坑）

### 1. 按批叫服务员，而不是一个一个叫

就绪的客人如果一次来 100 个，你要是一人一条消息往 channel 里塞，就是 100 次锁竞争。我改成**按 16 个一批打包**：

```rust
const DISPATCH_BATCH: usize = 16;

// 前台侧：就绪客人按 16 个一组发
if !to_dispatch.is_empty() {
    for chunk in to_dispatch.chunks(DISPATCH_BATCH) {
        let _ = ready_tx.send(chunk.to_vec());
    }
}
```

就像餐厅：铃响了，前台一次叫"3、4、5、6 号桌一起来"，而不是一桌一桌喊。

### 2. Windows 的坑：一次最多盯 64 个铃

Windows 的 `select` 有个硬限制：一次最多监视 64 个 socket（`FD_SETSIZE`）。所以 poller 得把客人**分批**盯。

这里藏着一个新手必踩的坑：**如果每一批都用完整超时（比如 5ms），那么第 3 批的客人，要等前两批各 5ms，一共 15ms 才轮到。** 批越多，延迟越大，还是乘法增长。

我改成：**只有第一批用完整超时，后面所有批都用零超时**——扫一眼就走，有就收，没有立刻下一批：

```rust
// 第一批用完整超时，之后每批零超时：
// 第 k 批就绪的 socket，绝不被前 k-1 批的超时拖累
let batches = self.fds.len().div_ceil(FD_SETSIZE).max(1);
for b in 0..batches {
    let tv = if b == 0 { &full_tv } else { &zero_tv };
    let n = select(0, &mut readset, &mut writeset, null_mut(), tv);
    // ...
}
```

（顺带说一句，哨子的耳朵被加进了**每一批**的读集合里，所以哨子永远能打断第一批的睡眠。）

### 3. Windows 的另一个坑：系统定时器太粗

Winsock `select` 的唤醒粒度受系统定时器对齐影响。Windows 默认的定时器分辨率可能到 15.6ms——也就是说，哪怕数据已经到了，你的 `select` 也可能因为"对齐到下一个定时器 tick"而多等十几毫秒。

解法是把进程定时器分辨率提到 1ms：

```rust
#[cfg(windows)]
pub(crate) fn ensure_high_resolution_timer() {
    static INIT: std::sync::Once = Once::new();
    INIT.call_once(|| {
        unsafe { timeBeginPeriod(1); }   // winmm，进程级提升到 1ms
    });
}
```

这个坑很隐蔽：它不会让你的程序"出错"，只会让延迟"莫名其妙地粗"。你不测延迟尾部（P99），根本发现不了。

---

## 慢客人：服务员介入之前就把问题挡掉

餐厅里最烦人的客人有两种：**点菜说半句就停住的**（Slowloris，一个字一个字蹦请求），和**吃完赖着不走的**（keep-alive 羊群）。

我们的架构对这两种人天生免疫，因为原则是：**客人没有真正按铃，服务员就永远不来。**

- 新客人进门，先是**非阻塞**的，挂在 poller 上——不占服务员；
- 只有数据真的到了（按铃），才派服务员；
- 服务员用**增量解析器**处理——请求没读完就回到"待着"状态，重新挂回 poller，**不占服务员**；
- 分类（TLS / h2 / h1）用 `peek` 看前几个字节，不消费数据——**再慢的客户端也卡不住接客线程**；
- `idle_timeout` 定期清走超时没动静的客人；
- `max_connections` 从门口就限流。

```rust
// 增量解析器：所有解析状态都住在这里，
// 半截请求可以挂起，下次唤醒时原样恢复。
struct IncrRequest {
    buf: Vec<u8>,       // 没消费的原始字节
    pos: usize,         // 消费到哪了
    line: Vec<u8>,      // 当前半截行
    phase: Phase,       // 请求行 / 头 / 体 / 完成
    // ...
}
```

---

## 证据：这些不是设计稿上的话，是 CI 里跑出来的

这是 `Github_Action_Benchmark.md` 里的真实数据（每 PR 都跑，失败挂流水线）：

### 200 条"点菜点一半"的客人 + 只有 2 个服务员

| 模型 | 结果 | 快速路径探测 |
|---|---|---|
| **事件驱动（哨子）** | `probe_ok` | **295µs** 完成一次新请求 |
| 旧模型（一连接一池任务） | `probe_blocked` | 读超时——服务员全被半截客人占满了 |

### 16 条 Slowloris（逐字节蹦请求头，10ms 一个字）+ 2 个服务员

| 模型 | 结果 | 探测 |
|---|---|---|
| **事件驱动** | 16/16 全部完成 | **532µs** 完成新请求 |

同样的思路用在 HTTP/3 的 UDP reactor 上，把周期性 `select()` 唤醒停顿消除了：**P99 从 10.7ms 降到 ~0.3ms。**

原始日志长这样：

```text
CONCURRENCY|case=idle_partial_herd|model=event|platform=linux|status=probe_ok|connections=200|worker_threads=2|probe_us=295.48
CONCURRENCY|case=idle_partial_herd|model=pool|platform=linux|status=probe_blocked|connections=200|worker_threads=2|probe_us=na
CONCURRENCY|case=slow_sender_herd|model=event|platform=linux|status=ok|connections=16|worker_threads=2|probe_us=532.82|byte_delay_us=10000|wall_ms=395.22
```

---

## 最后说点心里话

这个设计的技术含量，说实话不在"自管道"本身——这个技巧 Unix 程序员用了三四十年了。真正的价值在于**那个 5ms 的 P99 尖峰教会我的事**：

> **你花在"等下一个 tick"上的时间，就是用户请求延迟的一部分。** 除非你专门设计一个机制，让"有事发生"这件事本身能打断你的等待。

很多性能问题，不是"代码太慢"，而是**"没事做的时候太慢"**。你把循环写得多快都没用，因为瓶颈是"它多久醒一次"。self-pipe 解决的正是"醒来"这件事。

而慢连接羊群、keep-alive、SSE——这些"大多数时间没事做"的连接，才是真实互联网上占比最高的东西。**一个服务器的真实水平，往往取决于它怎么对待"没事做"的连接。** 这个调度器就是我们对这个问题的回答。

---

*上一篇：[一个 WINDOW_UPDATE 的小问题](./02-bcr-flow-control.md)*
