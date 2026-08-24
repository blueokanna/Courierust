# courierust_grpc

没有依赖树的 gRPC。gRPC 就是 HTTP/2 + 长度前缀二进制消息 + `grpc-status` 元数据——在这里实现于 crate 自己的客户端和服务端之上。没有 tonic、没有 prost、没有 tower。

## 里面有什么

- **全部四种调用形态**——unary、服务端流、客户端流、双向流，客户端服务端都有。
- **Deadline**——客户端发送 `grpc-timeout`，服务端强制执行（畸形 → `INVALID_ARGUMENT`，过期 → `DEADLINE_EXCEEDED`）。
- **元数据与拦截器**——任意元数据 + 客户端 `Interceptor` 钩子。
- **负载均衡**——`dns:///` 目标对解析出的地址做轮询。
- **健康**——`grpc.health.v1.Health` 的 `Check`（unary）和 `Watch`（服务端流）；无 reflection。
- **压缩**——`gzip` 和 `identity` 消息压缩，完整协商（gRPC A6）。gzip codec **从零实现**（`compress`）：解压处理任意标准生产者的 DEFLATE（stored/fixed/dynamic），解压后大小在两端都被 `max_message_size` 约束，压缩炸弹绕不过大小限制。

## 电池全包的部分

- **`proto`**——从零写的 protobuf 线上编解码（varint、定宽、length-delimited、packed repeated、ZigZag、有界嵌套）。零第三方 crate。
- **`generated`**——构建期代码生成：`build.rs` 把每个 `proto/*.proto` 编译成类型安全、IDE 友好的 Rust 结构体 + 线上编解码 + 类型化 gRPC 客户端 stub。官方 `proto/helloworld.proto` 作为 `generated::helloworld` 随附；放你自己的 `.proto` 文件进去，自动生成。

如果你已经有 protobuf 生态，也不会被锁死——`EncodeMessage` / `DecodeMessage` 是接缝。为你的类型实现它们（或包一层 prost），其他一切都直接工作。

## 诚实的边界

无 reflection 服务（需要 protobuf schema 注册表——外部职责）。服务端无拦截器。默认每消息 4 MiB 是硬上限——更大的载荷请显式设置 `max_message_size`。

## 用法

```rust
use courierust::courierust_grpc::{GrpcClient, GrpcServer};

// 服务端：实现 Service，或直接传闭包
let server = GrpcServer::bind("127.0.0.1:50051", |method: &str, req: Bytes| {
    Ok(Bytes::from(format!("echo({method}): {}", String::from_utf8_lossy(&req))))
})?;
let _h = server.serve_background()?;

// 客户端
let client = GrpcClient::new("http://127.0.0.1:50051")?;
let reply = client.call("helloworld.Greeter/SayHello", Bytes::from("world"))?;
```

`examples/grpc_streaming.rs` 演示四种调用形态、deadline、gzip 协商、元数据与拦截器；`examples/grpc_health.rs` 演示 `Check` + `Watch`。
