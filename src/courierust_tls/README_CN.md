# courierust_tls

TLS 1.2 + TLS 1.3，**从零实现、零依赖**，跑在本 crate 的 `Read`/`Write` 传输 trait 上。这是所有人都劝我别手写的那部分。我还是写了，因为我想让 `https://` 成为一等公民，而且我和 RFC 之间没有任何别人的代码。

## 密码学配置

**TLS 1.3（RFC 8446）：**

- 套件：`TLS_CHACHA20_POLY1305_SHA256`、`TLS_AES_128_GCM_SHA256`、`TLS_AES_256_GCM_SHA384`；
- 密钥交换：X25519；
- 证书签名验证：RSA-PSS / RSA PKCS#1 v1.5、ECDSA P-256、Ed25519。

**TLS 1.2（RFC 5246 / RFC 8422）：** 仅 AEAD 的 ECDHE 套件——三个 `ECDHE-ECDSA-*` 和三个 `ECDHE-RSA-*`（AES-128/256-GCM、CHACHA20-POLY1305、secp256r1）。没有 CBC/HMAC、没有 RC4、没有静态 RSA，永远没有。RFC 5746 `renegotiation_info` 会发送并回显。

所有原语都在 `crypto/`——ChaCha20、Poly1305、ChaCha20-Poly1305、AES、GCM、SHA-256/384、HMAC、HKDF、X25519、Ed25519、ECDSA、RSA，以及一个 OS 种子的 ChaCha20 DRBG——按公开规范实现，**无 unsafe**。

## 你平时看不见的验证

- X.509 链校验：有效期、名称链、签名验证、basic-constraints / key-usage、可插拔根证书库。
- RFC 6125 主机名校验，含 IP SAN、单通配符，以及 CVE-2025-61727 排除子树通配符规则。
- EKU 强制——带 EKU 扩展的叶子证书必须允许 `serverAuth`。
- RFC 8446 §4.1.3 **降级哨兵**写入并检查：纯 TLS 1.3 客户端遇到 TLS 1.2 ServerHello 直接拒绝，绝不静默降级。
- 两个版本都做常量时间的 `Finished` `verify_data` 比较和逐方向序列号（被篡改的记录报 `bad_record_mac`）。
- 解密握手缓冲区 16 MiB 上限，对端无限流握手记录也涨不爆内存。
- 两端都有 `handshake_timeout`（默认 10s）——握手中途停摆的对端会释放它的 worker/调用者。

## 诚实的边界

无 0-RTT / early data。TLS 1.3 会话恢复已实现——服务端签发 session ticket、1-RTT PSK `psk_dhe_ke`、按主机名分键的客户端会话缓存（上限 8 条）——并有单元测试；但池化客户端目前每个请求新建 connector，跨连接恢复尚未实际生效。QUIC 的 key update 在传输层经 key-phase 位处理（RFC 9001 §6）；记录层 TLS 1.3 KeyUpdate 消息不发送。无 mTLS——服务端从不请求客户端证书。`verify: false` 为测试/不可信对端而存在，但仍然验证 `CertificateVerify` + `Finished`，握手在密码学上保持健全。

## 用法

```rust
use courierust::courierust_tls::{RootStore, Identity};

let mut roots = RootStore::new();
roots.add_der(root_der);            // 无内置 CA——自带根

let identity = Identity {
    cert_chain: vec![cert_der],     // 叶子在前
    private_key: key_der,           // PKCS#8 或 PKCS#1（DER）
    is_rsa: false,                  // Ed25519/ECDSA 为 false
};
```

客户端（`ClientConfig` 的 `TlsSettings`）和服务端（`ServerConfig` 的 `TlsSettings`）接入这套；ALPN 决定 `h2` / `http/1.1` / `h3`。`examples/https.rs` 和 `examples/h3.rs` 是可跑的端到端示例。
