# gRPC 使用指南

gRPC = HTTP/2 + 长度前缀的二进制消息 + 由 trailer（`grpc-status` / `grpc-message`）携带的状态。Courierust 在自研 HTTP/2 栈之上实现了分帧、流式与状态处理。**protobuf 本身不包含**——你接入自己的编解码（prost、手写编码器或直接用原始字节）。

## 原始字节 unary 调用

```rust
use courierust::bytes::Bytes;
use courierust::grpc::GrpcClient;

let client = GrpcClient::new("http://127.0.0.1:50051")?;

// method 格式为 "package.Service/Method"
let reply = client.call("helloworld.Greeter/SayHello", Bytes::from("world"))?;
println!("{}", reply.to_str()?);
```

`GrpcClient::new` 内部为你构造一个 HTTP/2（h2c）客户端。没有握手步骤——第一次调用自动建连。

## 带类型编解码的 unary 调用

`String` 和 `Vec<u8>` 已经实现 codec trait，开箱即用：

```rust
let reply: String = client.call_unary::<String, String>("/echo.Echo/Say", &"ping".into())?;
assert_eq!(reply, "echo:ping"); // 取决于服务器返回
```

自己的 protobuf 类型实现两个 trait 即可：

```rust
use courierust::grpc::codec::{DecodeMessage, EncodeMessage};
use courierust::Result;

// 生成的/protobuf 消息，例如 `HelloRequest { name: String }`
struct HelloRequest { name: String }

impl EncodeMessage for HelloRequest {
    fn encode_message(&self) -> Result<Vec<u8>> {
        // ... 用你的 protobuf 库序列化 self.name ...
        Ok(self.name.as_bytes().to_vec())
    }
}

impl DecodeMessage for HelloRequest {
    fn decode_message(bytes: &[u8]) -> Result<Self> {
        Ok(HelloRequest { name: String::from_utf8_lossy(bytes).into_owned() })
    }
}
```

然后 `client.call_unary::<HelloRequest, HelloResponse>(...)`。

## 服务端流（一个响应多条消息）

```rust
use courierust::grpc::GrpcClient;

let client = GrpcClient::new("http://127.0.0.1:50051")?;
let mut stream = client.call_stream("/chat.Chat/Updates", courierust::bytes::Bytes::from("join"))?;

while let Some(msg) = stream.next_message()? {
    println!("msg: {}", msg.to_str()?);
}
```

`next_message()` 在流耗尽且 `grpc-status` 校验通过后返回 `None`；非 OK 状态会以 `Err` 形式暴露。

## 服务器

gRPC 服务是任意 `Fn(&str, Bytes) -> Result<Bytes> + Send + Sync + 'static`（或实现 `Service` trait 的类型）：

```rust
use courierust::bytes::Bytes;
use courierust::grpc::GrpcServer;

let server = GrpcServer::bind("127.0.0.1:50051", |method: &str, req: Bytes| {
    match method {
        "/echo.Echo/Say" => Ok(Bytes::from(format!("echo:{}", req.to_str()?))),
        _ => Err(courierust::Error::grpc(
            courierust::grpc::status::UNIMPLEMENTED,
            "unknown method",
        )),
    }
})?;
let addr = server.local_addr()?;
let _handle = server.serve_background()?; // 或 server.serve()? 阻塞
```

返回带 `grpc` 错误码的 `Err` 会映射为线上的 `grpc-status` / `grpc-message`。全部标准错误码都在 `courierust::grpc::status` 里（`OK`、`CANCELLED`、`INVALID_ARGUMENT`、`NOT_FOUND`、`INTERNAL`、`UNIMPLEMENTED`、`UNAVAILABLE` 等）。

## 客户端错误处理

```rust
match client.call("/x.Y/Z", Bytes::from("x")) {
    Ok(_) => {}
    Err(e) => {
        if let Some(code) = e.grpc_code() {
            println!("grpc status: {code}"); // 5 = NOT_FOUND, 等
        }
    }
}
```

`Error::grpc(code, msg)` 构造 gRPC 错误；`e.grpc_code()` 读回错误码。在 handler 里要返回错误响应，可用 `grpc::grpc_error_response(code, message)` 直接拿到现成的错误 `Response`。

## 分帧细节（只有需要时才关心）

- 每条消息 = `1 字节压缩标志 + 4 字节大端长度 + 负载`。
- `grpc::frame_message(payload, false)` 帮你完成这个分帧。
- `grpc::percent_decode(s)` 解码 `grpc-message` trailer 里百分号转义的 UTF-8。
- `grpc::MAX_MESSAGE_SIZE`（4 MiB）是分帧层接受的单条消息大小上限。
