# 协议对照与证据

基准用于发现实现差距和协议错误。对照对象选用各协议的主流独立实现；不存在脱离负载、配置和部署条件的“最好”。不能用 HTTP/1.1 请求速率证明 HTTP/2 更快，也不能把 TLS 握手、连接复用和纯 HTTP 混成一个排名。

根库仍然没有第三方依赖。对照库、protobuf 生成工具及其锁文件均属于本工作区；使用 Rust 1.98.0 和 `--locked`。具体版本见 `Cargo.lock` 及每次保存的依赖清单。

## 对照矩阵

| 协议 | 独立对照 | 实际覆盖与控制条件 | 尚未证明的能力 |
| --- | --- | --- | --- |
| HTTP/1.1 | [hyper](https://hyper.rs/) 服务端、reqwest 客户端 | 两客户端对同一 hyper 服务端；同一 reqwest 客户端对两个服务端；明文、1 KiB / 64 KiB、串行与并发分别报告，完整消费响应 | TLS 成本、跨机拥塞、慢客户端长期占用 |
| HTTP/2 | [hyper](https://github.com/hyperium/hyper) / h2、reqwest async | h2c prior knowledge；同对端矩阵；1 KiB / 64 KiB；连接数和并发扫描；校验协议、状态与全部字节 | 两客户端连接池策略不等价；大请求流控用例是诊断，不能直接作为速度排名 |
| HTTP/3 | [Quinn](https://github.com/quinn-rs/quinn) + [h3](https://github.com/hyperium/h3) | 两个 H3 客户端复用连接请求同一 Courierust H3 服务端，1 KiB / 64 KiB；真实握手及正文校验；失败保留 `not_available` | 尚无 Courierust 客户端对 Quinn/h3 服务端的性能行；没有完整的真实丢包、重排、迁移对照 |
| TLS 1.2 | [rustls](https://github.com/rustls/rustls)，aws-lc provider | 客户端 × 服务端 2 × 2；ECDHE-ECDSA-AES128-GCM-SHA256、P-256；同证书、校验开启、恢复关闭、相同 ALPN；完整握手和 1 KiB / 64 KiB 回显分开 | 其他密码套件、双向认证、恢复性能；互通不是密码安全审计 |
| TLS 1.3 | 同上 | 独立的 2 × 2 矩阵；AES128-GCM-SHA256、X25519，其余策略同上 | 0-RTT、长期密钥轮换和不同密码套件的性能 |
| gRPC | [tonic](https://github.com/grpc/grpc-rust) + prost | 两客户端 × 两服务端 × 四种调用形态 × 1 KiB / 64 KiB；h2c、共享 schema/编码器、identity 压缩、单连接；校验序号、字节和最终状态 | 有限消息流不证明交互式全双工；Courierust 服务端目前收齐请求再调用服务，尚无端到端流式背压 |
| WebSocket | [tungstenite / tokio-tungstenite](https://github.com/snapview/tungstenite-rs) | 三客户端 × 两服务端；64 B / 1 KiB / 16 KiB / 256 KiB 二进制回显；ws、无压缩、单连接、NODELAY、两端无 socket 超时；校验 opcode 与全部字节 | 本矩阵未测 wss、压缩、推送和慢消费者；Tokio 每次操作的 runtime 入口成本包含在计时内 |

`interop` 单独验证真实 socket、路径隔离、POST、连接复用、多路复用和流控。`h3` 上传/下载是本地诊断，不是独立实现对照。OpenSSL、curl、nginx 和 rustls/hyper TLS 外部互通由 `tls-interop.yml` 执行，本地回显不能代替该工作流。

## 运行与复核

Windows 在仓库根目录运行，需要 Rust 工具链和 Git Bash。protobuf 编译器由锁定的构建依赖提供。

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/run_protocol_comparisons.ps1 -Requests 128 -Repetitions 4 -Warmup 8
```

脚本先构建，再串行运行六个 release suite，避免编译抢占测试资源。它从 Cargo JSON 产物中读取实际可执行文件路径，不猜测旧文件。失败或超时会保留日志、写出报告并使脚本失败。默认输出 `target/protocol-comparison`：

| 文件 | 用途 |
| --- | --- |
| `REPORT.md` | 对照表、逐轮结果、样本数、退出状态、未运行项 |
| `*.log` / `*.stderr.log` | 原始数据和诊断，不能只保留最快一次 |
| `suite-status.json` | 每个 suite 的退出码；成功行不能覆盖失败 |
| `benchmark-environment.log` | UTC、OS、CPU、工具链、Git 状态、参数、锁文件哈希 |
| `source-sha256.txt` | 工作树文件哈希，包含未提交修改 |
| `benchmark-dependencies.json` | Cargo 解析的依赖版本及来源 |
| `build-artifacts.jsonl` | 本次构建产生的可执行文件及编译信息 |
| `suite-timing.json` | 各 suite 的实际开始时间与耗时 |

独立运行完成后，用 `powershell -File scripts/summarize_protocol_study.ps1 -Directory target/protocol-study` 生成 `statistics.json`。汇总要求至少两次运行、源码清单一致、六个 suite 全部成功且每个有效配置的重复数一致；失败日志不能截取成功行后混入排名。输出保留每次运行的中位数及范围，不将范围当作置信区间。

单独运行协议：

```bash
cargo +1.98.0 bench --manifest-path benches/Cargo.toml --locked --bench grpc
cargo +1.98.0 bench --manifest-path benches/Cargo.toml --locked --bench tls
WS_BENCH_SECTION=compare cargo +1.98.0 bench --manifest-path benches/Cargo.toml --locked --bench ws
cargo +1.98.0 bench --manifest-path benches/Cargo.toml --locked --bench compare
cargo +1.98.0 bench --manifest-path benches/Cargo.toml --locked --bench interop
```

`BENCH_REQUESTS` 设置每轮调用数，`BENCH_REPETITIONS` 设置重复次数。gRPC/TLS/WS 用 `BENCH_WARMUP`，预热不计时；HTTP 对照保留各用例自己的预热逻辑。HTTP 大请求诊断默认每轮至多 32 次。`h3` 诊断使用 `BENCH_RUNS`，与矩阵的重复参数不同。运行环境和日志 `META` 是实际配置依据。

独立进程重复和大响应扫描：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/run_protocol_study.ps1 -Runs 3 -Requests 128 -Repetitions 4 -ResponseSweep
```

每次运行分别保存六个 suite 的报告，不把进程内重复冒充独立实验。`suite-timing.json` 保留开始时间及包含预热、连接建立和退出的进程总时长；行内 `elapsed_ms` 才是该负载的计时区间。`BENCH_RESPONSE_SWEEP=1` 增加 256 KiB、512 KiB、1 MiB、2 MiB、4 MiB 的 H1/H2 响应，保持同对端和完整字节校验。每组 HTTP 对照结束时关闭对应服务端。

TLS 成本诊断与吞吐矩阵分开执行：设置 `BENCH_TLS_DIAGNOSTICS=1` 后运行 `tls`。它报告 64 KiB 分配复制、四条 16 KiB AES-GCM 加解密，以及客户端 socket 读写调用数和墙钟耗时。`outside_socket_us` 包含密码运算、复制、验证、调度及插桩开销，不是 CPU 时间；socket 读取时间还包含等待对端。微基准不能与网络耗时直接相加，插桩结果也不能替代未插桩的吞吐结果。

gRPC 的自定义 tonic incoming 流逐连接设置并读取验证 `TCP_NODELAY`。正常比较强制开启；单独运行 `grpc` 时可用 `GRPC_SERVER_NODELAY=0` 做控制实验，不能将这种配置的不对称结果列入公平排名。没有同环境抓包及时间线，不能仅凭约 40 ms 的延迟认定是 delayed ACK。

gRPC 流式用例每次 RPC 有四条消息，`bytes` 是单条业务 payload 长度，`requests` 是完成的 RPC 数，不是消息数。TLS 完整握手包含 TCP 连接、socket 设置及握手验证；记录回显在已建立连接上计时，`bytes` 是单方向应用长度。WS 一次请求是一次完整回显。

## 结果判读

1. 先看 suite 退出状态，再看行状态和完成数。`not_available`、诊断行、缺失日志不能参与“更快”的结论；失败不能换成空正文或成功计数。
2. 固定 server、协议、载荷、并发和安全策略，再比 client；比较 server 时固定 client。不能选择不同对端或关闭一方证书校验。
3. gRPC/TLS/WS 保留每轮并轮换客户端顺序。HTTP 保留现有的多轮合并统计，不能当成独立单轮样本。没有跨协议总分。
4. 分位数用 nearest-rank。并发采样采用一个全局上限并分配给 worker。少于 1,000 个样本时 p99 标为探索性；超过门槛也不是置信区间或稳定性证明。
5. 这是闭环 loopback 负载，没有 coordinated-omission 校正；等待响应会漏掉开环过载的排队效应。不能直接推导线上 p99 SLO、容量和故障恢复时间。
6. 测量时停止编译、扫描和其他压测，保留环境及多次独立运行。跨机结果还需网络、CPU 配额、电源策略和丢包/延迟模型。

## 独立对照发现的错误

- 指纹 ClientHello 的两个 GREASE 扩展可能重名，rustls 拒绝握手。现保证类型不同，回归覆盖 256 种重复随机字节输入。[RFC 8446 §4.2](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2)
- TLS 应用数据曾按密文容量分片，使大包超过 16 KiB 明文边界。现按明文上限切分，每条记录检查密钥预算，写入失败后终止流。[RFC 8446 §5.1](https://www.rfc-editor.org/rfc/rfc8446.html#section-5.1)
- gRPC unary 现在消费最终状态并拒绝多余消息；首条响应后的错误和 deadline 由最终 trailers 传递。`grpc-timeout` 小时换算、非整数秒精度、ASCII/位数校验也已修复。[gRPC HTTP/2 协议](https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md)
- H3 下载路径、字节计数和错误处理已校正；WS 使用实际连接的 NODELAY，流水线等全部响应后才停表，重复测量取真实中位数。
- HTTP/2 会先发送已就绪的流式请求数据，再进入 socket 读取；每批限制消费消息数。请求数据源错误会重置对应流并传回调用者，不能把已发送前缀当作完整请求成功处理。

## 生产采用边界

通过测试只说明已覆盖用例满足断言。自研 TLS 密码实现、H3 复杂网络行为、gRPC 请求缓冲和无界消息通道，不能凭本地吞吐量宣称达到成熟实现的全部能力。这里没有独立安全审计证明或“零漏洞”认证。

HTTP/2 客户端和服务端共用 socket 就绪等待，`Body::Stream` 的数据和结束通知直接唤醒驱动；原始 `Body::Channel` 保留 5 ms 轮询回退，部分帧读取也保留有界超时。每条 HTTP/2 连接仍有驱动线程，并新增一对本地通知 socket，不能将此路径描述成单 reactor 管理所有连接。请求缓冲、无界通道和慢消费者的内存上界仍需单独评估。

AES-GCM 在支持 PCLMULQDQ 的 x86_64 上使用无查表的字段乘法，其他 CPU 保留逐位实现。标准向量、全部基向量组合和部分块差分测试验证算法一致性；这不是密码实现整体的独立审计。加速结果必须注明 CPU 特性，不能外推为 ARM 性能。

这次 GHASH 改动也没有消除 AES 其他路径的侧信道风险：当前 AES 软件轮函数和密钥扩展仍有依赖秘密数据的 S-box 查表。不能把硬件 GHASH 或 AES-NI 的局部属性写成整个 TLS 实现的恒定时间保证；这些路径仍需整改及独立密码审计。

HTTP/2 `SETTINGS_MAX_CONCURRENT_STREAMS=0` 现在阻止新流；此前将其作为“无限制”不符合 [RFC 9113 §6.5.2](https://www.rfc-editor.org/rfc/rfc9113.html#section-6.5.2)。默认无实际约束使用 `u32::MAX`，显式配置零的调用方应检查这一行为修正。

发送窗口耗尽时，空 DATA 的 `END_STREAM` 和 trailing HEADERS 仍须能够发送；它们不消耗流控额度。回归测试覆盖连接窗口为零、流窗口为零或负数，以及最后一段 DATA 恰好耗尽额度的情况。客户端和服务端的 channel 适配器共用按剩余缓冲容量分段入队的实现，保留未接收的后缀；服务端不再因入队失败而丢弃已取出的数据。此处限制的是传输发送队列，并没有把无界生产者通道变成端到端有界通道。

H2 在 socket 拒绝写入后先刷新旧批次，再编码新帧。此前缓冲写入器刷新旧尾部失败时尚未接收新数据，而连接层误以为新数据已被保留并清空了暂存，造成丢帧。回归测试以连续拒绝写入、期间追加多个流、随后恢复的顺序验证完整线缆字节；不依赖操作系统偶发超时来触发。

等待对端流名额的请求也执行超时预算，队列后方的短期限请求不会被前方请求遮挡。H1 已知长度正文直接读入最终分配，保留预读字节和下一条消息的边界；截断或读取失败不会把预先初始化的尾部作为正文返回。

H1 每次最多初始化并读取 64 KiB，不在第一次接收前初始化整个大正文。正文构建仍有分配，转成当前 `Bytes` 的共享存储仍有复制；这条路径不能称为端到端零拷贝。整块预初始化的候选实现曾在 4 MiB 复测中退化，未作为最终实现保留。

发布证据应包含 MSRV/stable 检查、Linux/macOS/Windows 测试、独立互通、持续 fuzz、长时间资源稳定性、慢读写与取消测试，以及部署环境负载结果。每项保留日志、版本和退出状态；未执行的项目不能补造结论。
