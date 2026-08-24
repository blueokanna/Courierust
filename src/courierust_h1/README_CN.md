# courierust_h1

客户端和服务端共享的 HTTP/1.x 线上辅助：请求行解析、头块读取、body 分帧（Content-Length / chunked）、头序列化。这是 HTTP/1.1 真正被*解析*的地方，而不是被建模的地方（那是 `courierust_http`）。

## 必须严格的那部分

**请求行解析**严格按 RFC 9112 §3：恰好三个 token（`METHOD SP target SP HTTP/x.y`）、版本必须有、尾随垃圾拒绝。原因不是学究气——是走私。如果代理和你的服务器对消息边界理解不一致，攻击者就能走私请求。严格的 token 解析是让"不一致"变得不可能的廉价方式。

**Chunked 分帧**是同一个故事。块大小、CRLF 终止符、trailer 段——都由*同一个*共享解析器解析，事件驱动的增量服务器路径复用这个精确的解析器（见 `courierust_server::event`）。两个代码路径对同一个请求理解不一致，正是代理背后走私发生的成因，所以只能有一个权威。

## 里面有什么

- `parse_request_line`——严格三 token 请求行。
- `read_headers_scratch`——带上限（行/头数/块大小）的头块读取，复用 `Scratch`，keep-alive 稳态零按请求分配。
- `body_length`——按 method + headers 判定 `None` / `Content-Length` / `chunked`。
- `read_body_fixed_scratch` / `read_body_chunked_scratch`——有界 body 读取（巨大的声明长度当场拒绝，而不是干等）。
- `parse_chunk_size`——块大小的唯一权威，阻塞与事件驱动两条路径共享。
- `write_request_head` / `write_response_head`——序列化。
- `keep_alive_requested` / `wants_close`——精确 token 的 `Connection` 语义（`closex` token *不会*关闭），两条服务器路径永不分歧。
- `is_hop_by_hop`——RFC 9110 逐跳字段表。

## 上限

每行 64 KiB、1024 个头、1 MiB 头块、body 上限来自配置。Slowloris 投喂在变成问题之前就被封顶。

## 用法

客户端和服务端直接调用这些。如果你在写自己的 h1 传输，这是该复用的解析层——它共享是有原因的。
