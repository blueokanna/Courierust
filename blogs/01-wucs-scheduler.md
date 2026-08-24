# HTTP/2 的优先级：一个让大家都放弃的功能，我把它做成了 O(1)

## 先说个不好意思的事

做 Courierust 的时候，HTTP/2 的优先级，我本来是打算**直接跳过的**。理由很充分：

RFC 7540 给 HTTP/2 设计的优先级是一棵**依赖树**——每个流可以挂在另一个流下面，还带权重，意思大概是"我这个流要先等那个流到一半才能开始"。听着很美好，但现实是：**连 Chrome 都公开宣布弃用这套东西**，因为它太复杂，服务器端实现质量参差不齐，你精心排的依赖树，对端根本不认。

所以行业里形成了默契：优先级这东西，"做了没人用，不做也没人骂"。哪个库都不想做。

直到 RFC 9218 出来，把模型整个换掉了。

---

## 转折：RFC 9218 把模型变简单了，但把难题留给了你

RFC 9218 说：别搞依赖树了，太复杂。每个流就两个属性：

- **urgency**：0 到 7 的整数，0 最急，默认 3；
- **incremental**：一个布尔，表示"这个响应能不能边收边用"。

就这么简单。两个属性，谁都会写。

但 RFC 9218 干了一件很"狡猾"的事：**它只规定了语义，没规定算法**。

它说"高 urgency 的流应该先被服务"，但它没说"怎么服务"。它甚至专门写了一节（§10）警告你：**不能让低优先级永远轮不上**——这叫 starvation（饿死），是明令禁止的。

你看，规范把最难的部分甩给了实现者：怎么做到"高的优先、低的也不饿死"，而且还得够快，快到一个热连接上每发一帧都能跑一次。

---

## 先想清楚：这个调度器到底要在什么场合跑

先别急着写代码。关键是搞清楚使用场景：

> 一条 HTTP/2 连接上可能同时有几十上百个流在抢带宽。每次要往线上发一帧数据（比如 16KB），调度器都得回答一次："**这一帧发给谁？**"

注意"**每次**"。这意味着调度器不是在"连接建立时"跑一次，也不是"每秒"跑一次，而是**每帧**跑一次。一条跑满的 h2 连接，每秒钟要发出几千帧，就要调用几千次调度器。

所以我的目标就三条：

1. **每帧 O(1)**——不能有排序，不能有堆，最好连循环都尽量短；
2. **反饥饿**——低 urgency 的流必须能等到服务，这是 RFC 的硬性要求；
3. **语义对**——incremental 的流要按"可以边收边用"的方式调度，non-incremental 的流不能乱插队。

外加一条来自项目的约束：整个调度器在 `no_std + alloc` 下运行，**零依赖、零分配**。

---

## 为什么排序和堆都不行：先举个生活中的例子

想象你是一家医院的急诊分诊台。

每天都有病人进来，分诊护士按病情严重程度分到不同队列：危重（urgency 0）进抢救室，中等（urgency 3）进观察区，感冒发烧（urgency 7）在走廊排队。

现在问题来了：**如果每次都把所有病人按病情重新排一遍序，再挑最重的看，会怎样？**

- 排序本身要花时间。病人多的时候，护士光排序就忙不过来；
- 更糟的是，**新病人随时会来**。每来一个就要重排一次，之前排的全白费；
- 而且排序解决不了饥饿：如果抢救室永远有危重病人，走廊里的感冒病人**永远轮不上**——这在医院是医疗事故，在 RFC 里就是 §10 明令禁止的 starvation。

堆（优先队列）也一样：它比全排序快（每次 O(log n)），但它本质还是"永远挑最重的"，**饥饿问题没解决**。你需要在"挑最重的"和"谁都饿不死"之间找一个平衡。

这个平衡，就是 DRR（Deficit Round Robin，赤字轮询）做的事情。

---

## 设计：8 个"分诊台"，每个都是一个 DRR

### 数据结构

我用了 8 个桶，对应 8 个 urgency 级别。每个桶里两条队列 + 两个记账字段：

```rust
struct Bucket {
    /// 非增量流：FIFO（按插入顺序，也就是流 ID 升序）
    non_incremental: VecDeque<u32>,
    /// 增量流：轮转（round-robin）
    incremental: VecDeque<u32>,
    /// DRR 赤字：这个桶已经"服务"了多少字节
    deficit: u32,
    /// DRR 配额：每次最多连续服务多少字节
    quantum: u32,
}
```

用生活话说：

- **每个桶是一个分诊台**：urgency 0 的台子在最前面，urgency 7 的在最后；
- **deficit + quantum 是"配额制"**：每个台子有一个"服务额度"（quantum），它每服务一个病人就消耗额度（deficit 增加）。额度用完了，这轮就轮到后面的台子——**这就是不饿死人的关键**；
- **incremental / non-incremental 是两种病人**：
  - incremental 的病人"边看边走"——像**看直播**，数据边到边播，不需要等整场直播下载完。所以这类流可以一直在桶里轮转，轮流喂；
  - non-incremental 的病人"必须看完整个疗程才能走"——像**下载安装包**，文件没下完，你啥也用不了。所以这类流要按来的顺序（流 ID 升序）排队，不能乱插队。

### 选择算法：固定扫 8 个台子

每次要发帧了，调用 `next(want)`，`want` 是这帧要发多少字节：

```rust
pub fn next(&mut self, want: usize) -> Option<u32> {
    // 从 urgency 0 扫到 7
    for u in 0..8 {
        let b = &mut self.buckets[u];
        // 增量流：永远可服务，服务完放回队尾（轮转）
        if let Some(sid) = b.incremental.pop_front() {
            b.incremental.push_back(sid);
            return Some(sid);
        }
        // 非增量流：额度够才服务，服务后记账
        if !b.non_incremental.is_empty() && b.deficit.saturating_add(want as u32) <= b.quantum {
            b.deficit = b.deficit.saturating_add(want as u32);
            return b.non_incremental.pop_front();
        }
    }
    // 8 个台子都"额度耗尽"了？翻页：赤字清零，重新来一轮
    let any = self.buckets.iter().any(|b| !b.non_incremental.is_empty());
    if any {
        self.rounds += 1;
        for b in self.buckets.iter_mut() {
            b.deficit = 0;
        }
        for u in 0..8 {
            let b = &mut self.buckets[u];
            if let Some(sid) = b.incremental.pop_front() {
                b.incremental.push_back(sid);
                return Some(sid);
            }
            if !b.non_incremental.is_empty()
                && b.deficit.saturating_add(want as u32) <= b.quantum
            {
                b.deficit = b.deficit.saturating_add(want as u32);
                return b.non_incremental.pop_front();
            }
        }
    }
    None
}
```

这 30 行代码里，藏着整个机制的核心。我一行行讲：

**第一步：从 urgency 0 往 7 扫。** 这是"高优先级优先"的实现——只要前面台子有可服务的，后面的台子就轮不到。

**第二步：incremental 流永远可服务，而且轮转。** `pop_front` 然后 `push_back`，意思是"服务完你，你回队尾等着，别插队"。多个 incremental 流轮流获得带宽，谁也不独占——这就是"直播流们分带宽"的正确姿势。

**第三步：non-incremental 流要过"配额关"。** `deficit + want <= quantum` 才放行。quantum 比如设成 16KB，那么一个 non-incremental 流最多连续占 16KB 的发送量，然后它的台子就"欠债"了（deficit 涨上去了），下一轮扫描就会跳过这个台子。

**第四步（最关键）：全部台子都欠债了怎么办？翻页。** `rounds += 1`，所有 deficit 清零，重新扫一遍。这就像食堂打饭：每个人一次最多打三勺，大家都打完一轮了，就重新开始一轮。

---

## 为什么这能保证"谁也饿不死"：再回到急诊室

假设现在只有两个流：一个 urgency 0（抢救室的危重病人），一个 urgency 7（走廊里的感冒病人），quantum = 1000 字节，每帧 100 字节。

发生什么？

1. 第 1 帧：扫描，台子 0 有货，服务 urgency 0（deficit = 100）；
2. 第 2 帧：还是台子 0 有货，服务 urgency 0（deficit = 200）；
3. …… 一直这样下去，urgency 0 连续拿到 10 帧，deficit 涨到 1000；
4. 第 11 帧：台子 0 的 `deficit + 100 > 1000`，**配额耗尽，跳过**；
5. 扫描继续往后退，来到台子 7——**感冒病人终于被看到了，拿到一帧**；
6. 之后所有台子都欠债，翻页，deficit 清零，重新开始。

所以结果是：urgency 0 拿到 10 帧，urgency 7 拿到 1 帧。**高优先级获得了压倒性多数，但低优先级永远等得到自己的那一份。** 这就是 RFC 9218 §10 要的"优先但不独占"。

这个行为不是我拍脑袋保证的，是被一个单元测试**钉死**的：

```rust
#[test]
fn no_starvation_across_urgencies() {
    // 模拟调用方：流 1 有数据就反复重新入队（连接层正是这么干的）
    let mut s = Scheduler::new(1000);   // quantum = 1000 字节
    s.add(1, Priority { urgency: 0, incremental: false });
    s.add(2, Priority { urgency: 7, incremental: false });

    let mut served = vec![];
    for _ in 0..16 {
        if let Some(sid) = s.next(100) {   // 每帧 100 字节
            served.push(sid);
            if sid == 1 { s.add(1, Priority { urgency: 0, incremental: false }); }
        }
    }
    // 前 10 帧全是 urgency 0（1000 字节 = quantum，配额打满）
    assert_eq!(&served[..10], &[1, 1, 1, 1, 1, 1, 1, 1, 1, 1]);
    // 第 11 帧必须是 urgency 7 —— 这就是"没被饿死"的证据
    assert_eq!(served[10], 2);
}
```

这个测试很值钱。它把你对"反饥饿"的理解，从一句"理论上应该不会"变成了"**这个行为永远成立，改坏了测试就红**"。以后谁重构调度器，这个测试就是护城河。

---

## 为什么是 O(1)：数学很简单

扫描固定 8 个桶，每个桶只碰队首的 1 到 2 个元素。没有排序（排序是 O(n log n)），没有堆（堆是 O(log n)），连一次内存分配都没有。**最坏情况就是扫 16 个元素**（8 桶 × 每桶 2 个操作）。

这就是"够快到每帧都跑得起"的底气。你可以在一条跑满的 h2 连接上，每发一帧都调用它，完全不用心疼。

---

## 让优先级真正"活"起来：解析 + 传输 + API

调度器本身是死的，得有人喂它。Courierust 里它是这么接进去的：

**1. 解析 `Priority` 头 / `PRIORITY_UPDATE` 帧**

RFC 9218 说优先级可以随首请求用 `Priority` 头字段传，也可以运行中用 `PRIORITY_UPDATE` 帧（类型 `0x10`）改。格式是 RFC 8941 的 dictionary，我写了个解析器，只认 `u=`（urgency）和 `i`（incremental），其他未知参数按规范忽略：

```rust
pub fn parse(s: &[u8]) -> Option<Self> {
    // 按逗号切 token，认 u= 和 i，未知参数忽略
    // "u=5, i"  → urgency 5, incremental
    // "u=9"     → 越界，忽略（保持默认 3）
    // "x=y, u=7" → 未知参数忽略，urgency 7
}
```

**2. 运行中改优先级**

客户端收到用户的意图后，一边发 `PRIORITY_UPDATE` 帧给对端，一边就地调用调度器的 `update` 把流挪到新桶：

```rust
pub fn update(&mut self, stream_id: u32, old: Priority, new: Priority) {
    if old == new { return; }
    self.remove(stream_id);
    self.add(stream_id, new);
}
```

**3. 直接暴露给用户**

普通用户不想手动解析头字段，所以我给了个一行 API：

```rust
use courierust::courierust_h2::priority::Priority;

let prio = Priority { urgency: 1, incremental: true };
let resp = client.execute_priority("http://127.0.0.1:8080/api", request, prio)?;
```

---

## 说说实话

这算法不是我的原创发明——DRR 是 1995 年的老算法，RFC 9218 的模型是 IETF 定的。我做的其实是三件事的**组合**：

1. 把 RFC 9218 的语义，翻译成一个**可证明反饥饿**的具体算法；
2. 把它压到 **O(1)**，让它真的能跑在每帧路径上（而不是像依赖树那样沦为摆设）；
3. 在 **no_std、零依赖、零分配** 的约束下写完，还配了一个钉死反饥饿行为的测试。

值钱的地方在于：**优先级这个功能，业界默认是放弃的。** 而我证明了它可以用 30 行代码、O(1) 的代价、正确地做出来。你不需要在"正确"和"便宜"之间二选一。

如果你问我优先级在真实互联网上有多大用——诚实地说，单连接内部它确实有效（你的客户端到你的服务器之间，它是真的在起作用）。它解决不了跨代理被忽略的问题，但**在自己的栈里，它是真的每帧都在按你的意图调度**。这就比"实现了但没人用"强太多了。

---

*下一篇：[一个 WINDOW_UPDATE 的小问题，我数了一下控制帧](./02-bcr-flow-control.md)*
