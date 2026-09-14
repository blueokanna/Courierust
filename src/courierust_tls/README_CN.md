# courierust_tls

TLS 1.2 + TLS 1.3，**从零实现、零依赖**，跑在本 crate 的 `Read`/`Write` 传输 trait 上。这是所有人都劝我别手写的那部分。我还是写了，因为我想让 `https://` 成为一等公民，而且我和 RFC 之间没有任何别人的代码。

## 密码学配置

**TLS 1.3（RFC 8446）：**

- 套件：`TLS_CHACHA20_POLY1305_SHA256`、`TLS_AES_128_GCM_SHA256`、`TLS_AES_256_GCM_SHA384`；
- 密钥交换：X25519；
- 证书签名验证：RSA-PSS / RSA PKCS#1 v1.5、ECDSA P-256、Ed25519。

**TLS 1.2（RFC 5246 / RFC 8422）：** 仅 AEAD 的 ECDHE 套件——三个 `ECDHE-ECDSA-*` 和三个 `ECDHE-RSA-*`（AES-128/256-GCM、CHACHA20-POLY1305、secp256r1）。没有 CBC/HMAC、没有 RC4、没有静态 RSA，永远没有。RFC 5746 `renegotiation_info` 会发送并回显。

所有原语都在 `crypto/`——ChaCha20、Poly1305、ChaCha20-Poly1305、AES、GCM、SHA-256/384、HMAC、HKDF、X25519、Ed25519、ECDSA、RSA，以及一个 OS 种子的 ChaCha20 DRBG——按公开规范实现。除了两处作用域明确的例外（AES-NI 内建包装、Windows 系统熵调用，各自带自己的 `#[allow(unsafe_code)]`），其余均为安全 Rust。

## 你平时看不见的验证

- X.509 链校验：有效期、名称链、签名验证、basic-constraints / key-usage、可插拔根证书库。
- RFC 6125 主机名校验，含 IP SAN、单通配符，以及 CVE-2025-61727 排除子树通配符规则。
- EKU 强制——带 EKU 扩展的叶子证书必须允许 `serverAuth`。
- RFC 8446 §4.1.3 **降级哨兵**写入并检查：纯 TLS 1.3 客户端遇到 TLS 1.2 ServerHello 直接拒绝，绝不静默降级。
- 两个版本都做常量时间的 `Finished` `verify_data` 比较和逐方向序列号（被篡改的记录报 `bad_record_mac`）。
- 解密握手缓冲区 16 MiB 上限，对端无限流握手记录也涨不爆内存。
- 两端都有 `handshake_timeout`（默认 10s）——握手中途停摆的对端会释放它的 worker/调用者。

## 远程会话恢复与密钥更新

无 0-RTT / early data。TLS 1.3 会话恢复已实现——服务端签发 session ticket、1-RTT PSK `psk_dhe_ke`、按主机名分键的客户端会话缓存（上限 8 条）——并且池化客户端按 authority 缓存 connector，一条连接上拿到的 ticket 会在下一条连接上提供（`tls_session_resumption_across_client_connections` 端到端证明）。`KeyUpdate`（RFC 8446 §4.6.3）已双向实现：收到更新则切换读方向密钥、对端要求响应时先回一个自己的更新；写方向在耗尽单密钥记录预算（§5.5）前主动 rekey；`request_key_update()` 可强制发起。QUIC 的密钥更新仍走传输层 key-phase 位（RFC 9001 §6）。`verify: false` 为测试/不可信对端而存在，但仍然验证 `CertificateVerify` + `Finished`，握手在密码学上保持健全。

## 双向认证（mTLS，TLS 1.3）

客户端认证在 TLS 1.3 over TCP 上已实现。服务端设置 `ServerConfig::client_auth`（`ClientAuth`：信任根 + `required`/`optional`），随后在 `EncryptedExtensions` 与 `Certificate` 之间发送 `CertificateRequest`；客户端在配置了 `ClientConfig::identity` 时以 `Certificate` + `CertificateVerify` 应答，未配置时以**空**证书列表应答——这是 RFC 8446 §4.4.2 规定的拒绝方式，而不是沉默。服务端校验客户端叶证书：是否锚定到 client-auth 信任根、是否在有效期内、是否带 `clientAuth` EKU，并要求 `CertificateVerify` 证明私钥持有；叶证书会记录给上层使用。

策略由服务端决定，且线上消息如实反映：要求认证而客户端拒绝 → `certificate_required` (116)；证书链不可用/不可验证 → `bad_certificate` (42)；未请求却发来证书 → `unexpected_message` (10)。告警会**真正发出**（在对端正在读取的应用密钥纪元中加密），拒绝是可观测的，而不是只靠关闭套接字暗示。

边界（明说而非暗示）：TLS 1.2 搭配 `client_auth` 会在握手时被拒绝（否则 TLS 1.2 服务端只能退化到自己的、更弱的一套认证）；QUIC/HTTP3 路径在启动时拒绝该组合——这里的 mTLS 指 TLS 1.3 over TCP。握手后认证（`Finished` 之后的 `CertificateRequest`）未实现：非空 request context 会被拒绝。

## 用法

```rust
use courierust::courierust_tls::{Identity, RootStore};

let mut roots = RootStore::new();
roots.add_der(root_der);            // 无内置 CA——自带根
roots.add_pem(ca_bundle_pem)?;      // ……或者 PEM 捆绑包（块之外的文本会被忽略）

// `from_pem_file` 解析证书链与私钥，并证明二者属于同一对；已有内存中的
// 文本/DER 时用 `Identity::from_pem(cert, key)` 或
// `Identity::from_der(chain, key)`，校验完全相同。可接受的私钥容器：
// PKCS#8（`PRIVATE KEY`）、PKCS#1（`RSA PRIVATE KEY`）、SEC1
// （`EC PRIVATE KEY`）——由 DER 自身决定，不看标签。`ENCRYPTED PRIVATE
// KEY` 会被指名拒绝；与叶子证书不匹配的私钥在加载时报错，而不是每个
// 握手都失败一次。
let identity = Identity::from_pem_file("cert.pem", "key.pem")?;
```

`Identity` 也是私钥停止流动的地方：它的 `Debug` 只打印证书链条数与私钥**长度**，绝不打印私钥字节，因此进入日志的 `ServerConfig` 不会泄漏私钥。

客户端（`ClientConfig` 的 `TlsSettings`）和服务端（`ServerConfig` 的 `TlsSettings`）接入这套；ALPN 决定 `h2` / `http/1.1` / `h3`。`examples/https.rs` 和 `examples/h3.rs` 是可跑的端到端示例。
