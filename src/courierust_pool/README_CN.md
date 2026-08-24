# courierust_pool

用于多核连接处理的工作窃取线程池。这是 Courierust 里"多核是真的多核"的那部分。

## 怎么工作的

- 每个 worker 一条**私有 LIFO** 队列——最近提交的任务在缓存里最热，所以要先跑它。
- **全局 FIFO** 存放外部提交的任务；worker 只有在本地队列空之后才去拿。
- 两者都空时，worker 从**随机对等 worker 本地队列底部偷最老的任务**——FIFO 端，也就是所有者最不可能碰的那个。经典工作窃取策略：既限制单 worker 空闲时间，又保持局部性。
- 空闲 worker 在条件变量上停车——**空闲的池零 CPU 消耗**。

worker 数默认 `std::thread::available_parallelism()`。这就是连接处理能真正跨核扩展的原因。

## 用在哪

- 服务端把 TLS 和 HTTP/2 连接（以及旧模型下的每一条连接）经池派发。
- 客户端的 h2 driver 跑在它上面。
- 任务可以派生子任务——需要转交工作的 handler 不会把池搞死锁。

## 微妙的细节

- 共享状态里用 `Weak<Worker>` 引用，避免池和 worker 之间的引用环。
- worker 停车时 bump 一个 `park_seq` 序列号；偷窃者用它作新鲜度提示，挑空闲最久的受害者。
- 从对等方 LIFO 底部（最老）偷是故意的：所有者反正马上要跑最新的任务，偷最老的那个竞争最少。

## 用法

```rust
use courierust::courierust_pool::ThreadPool;

let pool = ThreadPool::new();        // 默认逻辑核数
pool.spawn(move || { /* 处理一条连接 */ });
pool.join();
```
