# courierust_fingerprint

让你的客户端**看起来像浏览器**。JA3 / JA4 TLS 指纹 + 精确复刻的 Chrome HTTP/2 指纹——全部从零计算，零依赖。

TLS 本身刻意外部化（这个 crate 零依赖）。这个模块产出的是浏览器形态客户端会展示的*数据*：精确的密码套件、扩展、ALPN、HTTP/2 设置——直接喂给你的 TLS 层。

## 里面有什么

- **JA3**——`ja3_hash()` 产出标准 32 位十六进制指纹，与公开的 Chrome 记录一致（`cd08e31494f9531f560d64c695473da9`）。`ja3_string()` / `ja3()` 给你中间形态。
- **JA4**——`ja4()` 产出四段式 `t13d1516h2_…` 指纹，与规范示例一致。（JA4 需要 MD5 + SHA-256；都在 `courierust_crypto` 里实现，无依赖。）
- **Chrome HTTP/2 指纹**——`ChromeH2Fingerprint::chrome()` 给你 SETTINGS 项（含 `WINDOW_UPDATE` 和 `MAX_FRAME_SIZE`）、初始帧序，以及 `order_headers_chrome()`——按 Chrome 的方式重排你的头字段。
- **`TlsProfile`**——一次 TLS `ClientHello` 的结构化描述（密码套件、扩展、曲线、ALPN、签名算法）。`chrome_tls_profile()` 返回 Chrome 形态的那份。

## 为什么存在

服务端指纹识别（JA3/JA4/HTTP2 指纹）是 CDN 和反爬系统区分"真 Chrome"和"curl"的手段。如果你在写一个想看起来普通的客户端，你的 ClientHello 和 HTTP/2 设置就得跟 Chrome *一模一样*——不是"差不多"。这个模块把"一模一样"编码下来，并对照公开的 Chrome 记录验证过。

## 用法

```rust
use courierust::courierust_fingerprint::{chrome_tls_profile, ja3_hash, ja4, h2::ChromeH2Fingerprint};

let profile = chrome_tls_profile();
assert_eq!(ja3_hash(&profile), "cd08e31494f9531f560d64c695473da9");
assert_eq!(ja4(&profile), "t13d1516h2_8daaf6152771_e5627efa2ab1");

let fp = ChromeH2Fingerprint::chrome();
let settings = fp.settings_entries();
let ordered = fp.order_headers_chrome(&fields);
```

你的 TLS 层消费 `TlsProfile` 来构造 ClientHello；你的 h2 层消费 Chrome 的设置与顺序。Courierust 自己的 TLS 栈正是这么干的。
