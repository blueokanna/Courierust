# courierust_net

传输层：真实 socket 的 `Read`/`Write` 适配、事件驱动服务器背后的就绪轮询器、统计计数器、HTTP/3 路径用的 UDP reactor。

## 里面有什么

- **TCP 适配**——`&TcpStream` 和 `Arc<TcpStream>` 的 `Read`/`Write` 实现，把 `WouldBlock`/`TimedOut` 映射到 crate 的错误类别。`Arc<TcpStream>` 让一条连接在读和写之间共享一个 socket，而不需要自引用。
- **`poller`**——I/O 就绪引擎：Windows 上是 Winsock `select`（分批，第一批满超时，其余零超时），其他地方是 POSIX `poll`，每批都带一个可选的唤醒描述符（事件服务器的 self-pipe）。整个慢连接故事在这里——见 `blogs/03-self-pipe-event-scheduler.md`。
- **`stats`**——`Arc<AtomicUsize>` 计数器（连接数、h1/h2 系统调用、poll 系统调用、唤醒次数、队列深度峰值），基准套件把它们变成证据行。`Counting` 包装器让"这条连接到底做了多少次系统调用"可测量。
- **`udp`**——HTTP/3 runtime 驱动的 UDP socket reactor（非阻塞语义的数据报读写，Windows 上 timeBeginPeriod 1ms 分辨率）。

## 为什么 TCP 适配很讲究

`WouldBlock` 的映射比看起来重要：事件服务器把 socket 跑在非阻塞模式，所以每次 read 都可能合法地返回"还没就绪"。如果不把它作为一等公民的 `ErrorKind::WouldBlock` 浮出来，整个事件循环"挂起连接等就绪"的模型就塌了。这个映射做对了，codec 才能既与传输无关，事件循环又能诚实地对待背压。
这个映射还有后半段，只有超时被武装之后才看得到。Windows 把超时的 read 或 write 失败为 `WSAETIMEDOUT`，POSIX 失败为 `EAGAIN`——恰好是表示“还没就绪”的那个错误码。原始适配器把两者都折叠成 `WouldBlock`，连接层则记住自己交给 socket 的超时是**截止时间**（请求或关闭预算，到期本身就是一种结论）还是**轮询**（h2/h3 驱动用来交回控制权的短超时）。只有截止时间才把 `WouldBlock` 归一化为 `ErrorKind::Timeout`；轮询那侧保持 `WouldBlock` 不变。没有这个区分，`Client::request(..).timeout(d)` 会把 POSIX 独有的错误类别泄漏给调用者，而且按连接关闭定界的响应体会把到期当成干净 EOF——把截断的消息当成功返回。
同一条规则的写侧，决定了“发送缓冲区满了”会不会被当成“对端死了”。上传被对端的流控窗口牵着走，所以一次超出轮询超时的 `write` 就是正常背压：h2 会话留着这一帧，下一轮继续。少了这半条规则，故障就带上平台形状——Linux 的发送缓冲区大、`EAGAIN` 本来就表示“没就绪”，上传 1 MiB 毫无问题；Windows 的缓冲区小、`WSAETIMEDOUT` 又曾被当作致命错误，同一条代码路径上第三个请求就挂了。
## 用法

你很少直接碰它——`courierust_client` / `courierust_server` 在底层用它。但如果你在适配别的传输（管道、别处的 TLS 流），这是要抄的模式：实现 `courierust_io::Read`/`Write`，把你的阻塞状态映射到 crate 的错误类别，整个栈就能工作。
