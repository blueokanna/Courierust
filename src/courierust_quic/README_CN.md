# courierust_quic

QUIC v1 线上编解码（RFC 9000 / 9001 / 9002）：变长整数、长/短包头、包号、流 ID、RFC 9000 §19 的每一种帧类型，以及（`std` 下）RFC 9001 包保护。`no_std` 可编译、零依赖。

## 里面有什么

- **Varint**——RFC 9000 §16 的 `2^N` 长度前缀整数，对照附录示例测试。
- **包头**——长/短两种形式，按附录 A.2 的包号恢复。
- **流标识符**——类型/索引解码，客户端/服务端 × 双向/单向。
- **§19 的全部帧类型**，包括 ECN ACK（`0x03`）和 DATAGRAM。
- **包保护**（`protection.rs`，std）——RFC 9001 §5–6 的 AEAD + 头保护原语：经 HKDF-Expand-Label（`tls13 quic key` / `quic iv` / `quic hp`）的 TLS 1.3 密钥调度、v1 Initial salt、Retry 完整性标签、逐包号 nonce 构造。头保护掩码用完整密文块，不是截断的 sample。

## 设计决策

`protection.rs` 刻意**只管包保护**。包号空间、丢包恢复、流调度都在它上面的 runtime 里。让 AEAD 代码独立，意味着它能在不开 socket 的情况下对照 RFC 向量测试——线上原语在传输层碰到它之前就先在隔离环境里验证过了。

## 诚实的边界

这是内置 HTTP/3 runtime 所用到子集的完整实现：一条经过验证的 QUIC v1 路径，含 TLS 1.3、Retry 完整性与 token 绑定的地址验证、Version Negotiation、验证前服务端 3x 防放大、有界 CRYPTO/stream 重组、ACK range、用新包号的重传、RTT/RTO 采样、有界拥塞窗口。传输长尾已实现并有测试覆盖：完整 PTO/时间阈值丢包恢复、动态本地 `MAX_DATA`/`MAX_STREAM_DATA`/`MAX_STREAMS` credit、连接迁移与路径验证、stateless reset（生成与校验）、带单次保护的双向自动 key update、QPACK blocked-stream ack。刻意不做：0-RTT / early data，以及独立实现互操作。这两项是宣称对外普遍互通前的剩余事项。

## 用法

你大概也不会直接用这个——`courierust_h3` 的 runtime 通过 UDP reactor 驱动它。但如果你在写自己的 QUIC 传输，这里的 codec 是你可以信任并隔离测试的部分。
