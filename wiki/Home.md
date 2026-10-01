# Courierust

A self-contained HTTP/1.1 + HTTP/2 + HTTP/3 + WebSocket + gRPC stack for Rust with **zero third-party dependencies**. The protocol core (`courierust_http`, `courierust_hpack`, `courierust_h2`, `courierust_ws`, `courierust_deflate`, `courierust_quic`, `courierust_h3`, `courierust_fingerprint`, `courierust_crypto`, `courierust_bytes`, `courierust_io`, `courierust_error`) compiles under `no_std + alloc`; the `std` layer adds a work-stealing thread pool, a multi-core client (h1 pool, h2/h3 drivers, WebSocket client), a server (event-driven scheduler + in-place WebSocket upgrade), a built-in TLS 1.2 + 1.3 stack, and gRPC. All public modules carry the `courierust_` prefix so none of them collide with third-party crates of the same short name.

Every code sample below is real, runnable API usage.

## 中文教程

- [快速上手（5 分钟跑通客户端 + 服务器）](快速上手)
- [HTTP 客户端：配置、GET/POST、重定向、优先级、流式响应](HTTP-客户端)
- [HTTP 服务器：handler、流式响应、h2、后台运行](HTTP-服务器)
- [WebSocket：服务端升级、客户端、代理部署与安全策略](WebSocket-使用指南)
- [gRPC：Service、unary、服务端流、自定义编解码、错误码](gRPC-使用指南)
- [浏览器指纹：JA3 / JA4 / Chrome HTTP/2 指纹](浏览器指纹)
- [no_std：只用协议核心（嵌入式 / 内核态）](no_std-使用)
- [示例：25 个可直接运行的 demo](示例)
- [基准测试：自测、跨库对比与互操作验证](基准测试)

## English tutorials

- [Getting started (client + server in 5 minutes)](Getting-Started)
- [HTTP client: config, GET/POST, redirects, priorities, streaming](HTTP-Client)
- [HTTP server: handlers, streaming, h2, background serving](HTTP-Server)
- [WebSockets: server upgrade, client, proxy deployment, security policy](WebSockets)
- [gRPC: Service, unary, server-streaming, custom codecs, status](gRPC)
- [Fingerprints: JA3 / JA4 / Chrome HTTP/2](Fingerprints)
- [no_std: protocol core only (embedded / kernel)](no_std)
- [Examples: 25 runnable demos](Examples)
- [Benchmarks: self, cross-library comparison, and interop validation](Benchmarks)

## What the crate does

| Area | What you get |
|---|---|
| HTTP/1.1 | request/response parsing, keep-alive, chunked, `100-continue` |
| HTTP/2 (RFC 9113) | full frame codec, stream state machine, flow control |
| HTTP/3 (RFC 9114) | QUIC v1 + TLS 1.3 over UDP, QPACK, loss recovery, migration |
| WebSocket (RFC 6455 + 7692) | in-place upgrade on both server drivers, client over `ws://`/`wss://`, `permessage-deflate`, masking, close handshake, keepalive |
| Priorities (RFC 9218) | `PRIORITY_UPDATE` + a WUCS scheduler (O(1), anti-starvation) |
| HPACK (RFC 7541) | table-driven Huffman, static/dynamic tables, RFC vectors verified |
| Fingerprints | JA3 / JA4 / Chrome HTTP/2 profile (self-contained MD5/SHA-256) |
| Multi-core | work-stealing server pool, bounded client connection pools |
| gRPC | framing + status + codec traits (protobuf itself is plug-in) |
| TLS | built-in TLS 1.2 + 1.3 for client/server HTTPS (RFC 5246/8446); external transports are also supported |

## Repository

- Source: `https://github.com/blueokanna/Courierust`
- License: [PolyForm Perimeter 1.0.1](../LICENSE) — source-available, free for any purpose except a competing product; no warranty, no liability
