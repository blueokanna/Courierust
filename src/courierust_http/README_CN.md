# courierust_http

HTTP 消息模型：请求、响应、头、URI、状态码、版本、body。

这是整个栈的**词汇表**。上面每一层——h1、h2、h3、gRPC、client、server——都用这里定义的类型说话。如果整个仓库你只想先读一个模块，读这个。

## 为什么存在

每个协议层都需要一个共享的"HTTP 消息长什么样"的模型。最省事的做法是依赖 `http` crate。问题在于：我要协议核心在 `no_std` 下零依赖编译，而 `http` 做不到我需要的干净程度。所以手写。不难——只是总得有人干。

## 里面有什么

- `Request` / `Response`——消息容器。
- `HeaderMap` / `HeaderName` / `HeaderValue`——名字按 RFC 9110 token 校验，值按字节校验。没有"悄悄给你小写化"的惊喜；h2 伪头（`:method` 等）是一等公民。
- `Uri` / `PathAndQuery` / `Url`——absolute-form 和 origin-form 的目标，外加客户端用的绝对 URL 类型（scheme/authority 拆分）。
- `Method`、`StatusCode`、`Version`——你预期的那几个枚举，外加你总忘的那个（比如 `CONNECT`）。
- `Body`——这一层只有 `Empty` / `Bytes`。channel 背靠背的流式变体在 `courierust_body`（std 层），核心保持轻量、`no_std`。

## 设计决策

- **单一权威。** 整个栈没有任何其他地方重新实现"header 名字是什么"。校验错了，也只错在一个地方。
- **`no_std` 优先。** 这个模块不知道 socket 是什么。这是故意的——同一个模型既能在内核模块里跑，也能在服务器上跑。
- **该严的地方严。** Header 名是 token，不是"你随便敲的字节"。这里宽松，就是走私漏洞的起点。

## 边界

它是模型，不是编解码器。线上解析/序列化在 `courierust_h1` / `courierust_h2` / `courierust_h3`。这个模块只负责承载流过它们的状态。
