# courierust_body

std 层的消息 body：`Empty`、`Bytes`，以及 **`Channel`**——一个 mpsc channel 背靠背的流式 body。

## `Channel` 给你什么

handler 不必先把整个响应拼完再返回。用 `Body::Channel`，你交出接收端，从别的线程推块进来——SSE 式推送、流式文件读取、长轮询 feed。服务器消费 channel 并分帧（h1 用 chunked、h2 用 DATA 帧、h3 用字节）。

客户端这边，同一个类型承载随时间到达的响应体。

## 背压故事

h2 服务端路径是流控感知的：channel body **只在连接能接收更多数据时才被消费**。慢读端不会造成无界缓冲——服务器在对端流控窗口重新打开之前停止消费 channel。这就是"流式"和"永远缓冲"的区别。

## 用法

```rust
use courierust::courierust_body::Body;
use courierust::courierust_bytes::Bytes;
use std::sync::mpsc::channel;

let (tx, rx) = channel::<Result<Bytes>>();
// 把 `rx` 交给响应，从任何地方推：
tx.send(Ok(Bytes::from_static(b"chunk 1")));
```

`Result<Bytes>` 的载荷是故意的：生产者可以在流中报告错误，消费者看到的是错误，而不是被截断的 body。
