# gRPC

gRPC is HTTP/2 + length-prefixed binary messages + a status carried in trailers (`grpc-status` / `grpc-message`). Courierust implements the framing, streaming, and status handling on top of its own HTTP/2 stack. **Protobuf itself is not included** — you plug in your own codec (prost, a hand-written encoder, or raw bytes).

## Unary call with raw bytes

```rust
use courierust::bytes::Bytes;
use courierust::grpc::GrpcClient;

let client = GrpcClient::new("http://127.0.0.1:50051")?;

// method is "package.Service/Method"
let reply = client.call("helloworld.Greeter/SayHello", Bytes::from("world"))?;
println!("{}", reply.to_str()?);
```

`GrpcClient::new` builds an HTTP/2 (h2c) client for you. There is no connection handshake — the first call opens the connection.

## Unary call with a typed codec

`String` and `Vec<u8>` already implement the codec traits, so this works today:

```rust
let reply: String = client.call_unary::<String, String>("/echo.Echo/Say", &"ping".into())?;
assert_eq!(reply, "echo:ping"); // whatever your server returns
```

For your own protobuf types, implement the two traits:

```rust
use courierust::grpc::codec::{DecodeMessage, EncodeMessage};
use courierust::Result;

// Generated/protobuf message, e.g. `HelloRequest { name: String }`
struct HelloRequest { name: String }

impl EncodeMessage for HelloRequest {
    fn encode_message(&self) -> Result<Vec<u8>> {
        // ... serialize self.name with your protobuf library ...
        Ok(self.name.as_bytes().to_vec())
    }
}

impl DecodeMessage for HelloRequest {
    fn decode_message(bytes: &[u8]) -> Result<Self> {
        Ok(HelloRequest { name: String::from_utf8_lossy(bytes).into_owned() })
    }
}
```

Then `client.call_unary::<HelloRequest, HelloResponse>(...)`.

## Server-streaming (multiple messages in one response)

```rust
use courierust::grpc::GrpcClient;

let client = GrpcClient::new("http://127.0.0.1:50051")?;
let mut stream = client.call_stream("/chat.Chat/Updates", courierust::bytes::Bytes::from("join"))?;

while let Some(msg) = stream.next_message()? {
    println!("msg: {}", msg.to_str()?);
}
```

`next_message()` returns `None` once the stream is exhausted and the `grpc-status` has been checked (a non-OK status surfaces as an `Err`).

## Server

A gRPC service is any `Fn(&str, Bytes) -> Result<Bytes> + Send + Sync + 'static` (or a type implementing the `Service` trait):

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
let _handle = server.serve_background()?; // or server.serve()? to block
```

Returning `Err` with a `grpc` error code maps to `grpc-status` / `grpc-message` on the wire. All standard codes are in `courierust::grpc::status` (`OK`, `CANCELLED`, `INVALID_ARGUMENT`, `NOT_FOUND`, `INTERNAL`, `UNIMPLEMENTED`, `UNAVAILABLE`, …).

## Error handling on the client

```rust
match client.call("/x.Y/Z", Bytes::from("x")) {
    Ok(_) => {}
    Err(e) => {
        if let Some(code) = e.grpc_code() {
            println!("grpc status: {code}"); // 5 = NOT_FOUND, etc.
        }
    }
}
```

`Error::grpc(code, msg)` builds a gRPC error; `e.grpc_code()` reads it back. For returning errors from your own handler, the `grpc::grpc_error_response(code, message)` helper builds a ready-made error `Response`.

## Framing details (only if you need them)

- Each message is `1 byte compressed-flag + 4 bytes big-endian length + payload`.
- `grpc::frame_message(payload, false)` produces that framing for you.
- `grpc::percent_decode(s)` decodes the percent-escaped `grpc-message` trailer value.
- `grpc::DEFAULT_MAX_MESSAGE_SIZE` (4 MiB) is the default ceiling for a single message accepted by the framing layer, and it is configurable on both sides: `GrpcClientConfig::max_message_size` for the client and `GrpcServer::max_message_size` for the server. The uncompressed size is checked on both ends, so a compression bomb is rejected.
