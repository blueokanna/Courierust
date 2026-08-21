//! End-to-end gRPC demo: a background gRPC server plus a client that
//! calls it. Run with `cargo run --example greeter`.

use courierust::courierust_bytes::Bytes;
use courierust::courierust_grpc::{GrpcClient, GrpcServer};

fn main() -> courierust::Result<()> {
    // --- server ---
    // The service is a plain function (method, request bytes) -> Result.
    // A real deployment would route methods to protobuf handlers.
    let server = GrpcServer::bind("127.0.0.1:0", |method: &str, req: Bytes| match method {
        "/greeter.Greeter/SayHello" => {
            let name = if req.is_empty() {
                "world"
            } else {
                req.to_str()?
            };
            Ok(Bytes::from(format!("Hello, {name}!")))
        }
        "/greeter.Greeter/Count" => Ok(Bytes::from(format!("{} chars", req.len()))),
        _ => Err(courierust::Error::grpc(
            courierust::courierust_grpc::status::UNIMPLEMENTED,
            "unknown method",
        )),
    })?;
    let addr = server.local_addr()?;
    let _handle = server.serve_background()?;
    println!("gRPC server listening on {addr}");

    // --- client ---
    let client = GrpcClient::new(&format!("http://{addr}"))?;

    // Raw-bytes unary call.
    let reply = client.call("/greeter.Greeter/SayHello", Bytes::from("Courierust"))?;
    println!("SayHello  -> {}", reply.to_str()?);

    // Typed unary call (String implements the built-in codec).
    let reply: String =
        client.call_unary::<String, String>("/greeter.Greeter/SayHello", &"typed".to_string())?;
    println!("SayHello  -> {reply}");

    let reply = client.call("/greeter.Greeter/Count", Bytes::from("héllo"))?;
    println!("Count     -> {}", reply.to_str()?);

    // Error status surfaces as an Err carrying the gRPC code.
    match client.call("/greeter.Greeter/Nope", Bytes::from("x")) {
        Ok(_) => println!("unexpected success"),
        Err(e) => println!("Nope      -> grpc-status={:?} message={}", e.grpc_code(), e),
    }

    Ok(())
}
