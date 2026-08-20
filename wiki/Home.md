# Courierust

A self-contained HTTP/1.1 + HTTP/2 + gRPC stack for Rust with **zero third-party dependencies**. The protocol core (`http`, `hpack`, `h2`, `fingerprint`, `crypto`) compiles under `no_std + alloc`; the `std` layer adds a work-stealing thread pool, a multi-core client, a server, and gRPC.

This wiki is a hands-on guide. Every code sample below is real API usage — copy it, paste it, run it.

## 中文教程

- [快速上手（5 分钟跑通客户端 + 服务器）](快速上手)
- [HTTP 客户端：配置、GET/POST、重定向、优先级、流式响应](HTTP-客户端)
- [HTTP 服务器：handler、流式响应、h2、后台运行](HTTP-服务器)
- [gRPC：Service、unary、服务端流、自定义编解码、错误码](gRPC-使用指南)
- [浏览器指纹：JA3 / JA4 / Chrome HTTP/2 指纹](浏览器指纹)
- [no_std：只用协议核心（嵌入式 / 内核态）](no_std-使用)
- [示例：8 个可直接运行的 demo](示例)
- [基准测试：自测 + 与 hyper/reqwest/tiny_http 对比](基准测试)

## English tutorials

- [Getting started (client + server in 5 minutes)](Getting-Started)
- [HTTP client: config, GET/POST, redirects, priorities, streaming](HTTP-Client)
- [HTTP server: handlers, streaming, h2, background serving](HTTP-Server)
- [gRPC: Service, unary, server-streaming, custom codecs, status](gRPC)
- [Fingerprints: JA3 / JA4 / Chrome HTTP/2](Fingerprints)
- [no_std: protocol core only (embedded / kernel)](no_std)
- [Examples: 8 runnable demos](Examples)
- [Benchmarks: self + vs hyper/reqwest/tiny_http](Benchmarks)

## What the crate does

| Area | What you get |
|---|---|
| HTTP/1.1 | request/response parsing, keep-alive, chunked, `100-continue` |
| HTTP/2 (RFC 9113) | full frame codec, stream state machine, flow control |
| Priorities (RFC 9218) | `PRIORITY_UPDATE` + a WUCS scheduler (O(1), anti-starvation) |
| HPACK (RFC 7541) | table-driven Huffman, static/dynamic tables, RFC vectors verified |
| Fingerprints | JA3 / JA4 / Chrome HTTP/2 profile (self-contained MD5/SHA-256) |
| Multi-core | work-stealing pool, per-worker sharded connection pools |
| gRPC | framing + status + codec traits (protobuf itself is plug-in) |
| TLS | **not built in** — h2c / h1.1 directly, or drive the codec over any TLS stream |

## Repository

- Source: `https://github.com/blueokanna/Courierust`
- License: Apache-2.0
