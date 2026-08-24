# courierust_crypto

两个小摘要：**MD5**（RFC 1321，JA3 用）和 **SHA-256**（FIPS 180-4，JA4 用）。`no_std`、零依赖、无 unsafe。

## 为什么只有两个摘要

因为指纹层只需要这两个，而这个模块就是为它服务的。这不是密码学工具箱——TLS 栈自己那套完整原语在 `courierust_tls::crypto` 里（AES-GCM、ChaCha20-Poly1305、X25519、Ed25519、ECDSA、RSA、HKDF、HMAC）。这个模块刻意做得又小又无聊又正确。

## 重点

JA3 的全部戏法就是对一个规范化 ClientHello 字符串做 MD5；JA4 的前半段是对指纹第二段做 SHA-256。你需要在 `no_std` 零依赖下拿到这两个摘要。就这些。它们按公开规范实现，对照公开测试向量验证，不含 unsafe。

## 用法

```rust
use courierust::courierust_crypto::{md5, sha256};

let h = md5::md5(b"data");
let s = sha256::sha256(b"data");
```

或者干脆不用——指纹函数会替你调用。
