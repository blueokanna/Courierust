//! gRPC streaming demo — the call shapes `greeter.rs` does not show:
//! server-streaming, client-streaming and bidi, plus deadlines, gzip
//! compression negotiation and request metadata / interceptors.
//!
//! The service is `echo.Echo`:
//!   - `ServerStream` — one request ("5") -> `part-0` .. `part-4`
//!   - `ClientStream` — many requests -> one aggregated reply
//!   - `Bidi` — many requests -> one echo per request
//!   - `Slow` — sleeps, so a short deadline yields `DEADLINE_EXCEEDED`
//!
//! All framing runs on the crate's own HTTP/2 + gRPC stack; no protobuf
//! dependency — messages are raw bytes (implement `EncodeMessage` /
//! `DecodeMessage` for your types, or use the raw-bytes API).
//!
//! Run: `cargo run --example grpc_streaming`

use courierust::courierust_bytes::Bytes;
use courierust::courierust_client::Client;
use courierust::courierust_client::ClientConfig;
use courierust::courierust_grpc::status::DEADLINE_EXCEEDED;
use courierust::courierust_grpc::{GrpcClient, GrpcClientConfig, GrpcServer};
use courierust::courierust_http::header::{HeaderMap, HeaderName, HeaderValue};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};
use std::time::Duration;

fn main() -> courierust::Result<()> {
    let server = GrpcServer::bind_streaming(
        "127.0.0.1:0",
        |method: &str,
         reqs: &mut dyn Iterator<Item = courierust::Result<Bytes>>,
         tx: &courierust::courierust_body::BodySender|
         -> courierust::Result<()> {
            match method {
                "/echo.Echo/ServerStream" => {
                    let count = reqs
                        .next()
                        .transpose()?
                        .unwrap_or_default()
                        .to_str()?
                        .parse::<u32>()
                        .unwrap_or(0);
                    for i in 0..count {
                        tx.send(Bytes::from(format!("part-{i}")))?;
                    }
                    Ok(())
                }
                "/echo.Echo/ClientStream" => {
                    let mut total = 0usize;
                    for req in reqs {
                        total += req?.len();
                    }
                    tx.send(Bytes::from(format!("sum={total}")))?;
                    Ok(())
                }
                "/echo.Echo/Bidi" => {
                    for req in reqs {
                        let req = req?;
                        tx.send(Bytes::from(format!("echo:{}", req.to_str()?)))?;
                    }
                    Ok(())
                }
                "/echo.Echo/Slow" => {
                    // Outlive any short deadline so DEADLINE_EXCEEDED is
                    // observed server-side.
                    std::thread::sleep(Duration::from_secs(1));
                    tx.send(Bytes::from_static(b"done"))?;
                    Ok(())
                }
                _ => Err(courierust::Error::grpc(
                    courierust::courierust_grpc::status::UNIMPLEMENTED,
                    "unknown method",
                )),
            }
        },
    )?;
    let addr = server.local_addr()?;
    let _handle = server.serve_background()?;
    println!("gRPC streaming server on {addr}");

    let client = GrpcClient::new(&format!("http://{addr}"))?;
    let mut stream = client.call_stream("/echo.Echo/ServerStream", Bytes::from("5"))?;
    let mut parts = Vec::new();
    while let Some(msg) = stream.next_message()? {
        parts.push(msg.to_str()?.to_string());
    }
    println!("ServerStream(5) -> {parts:?}");
    assert_eq!(parts, ["part-0", "part-1", "part-2", "part-3", "part-4"]);

    let (tx, rx) = mpsc::channel();
    for word in ["hello", " ", "gRPC", " ", "streaming"] {
        if tx.send(Ok(Bytes::from(word.to_string()))).is_err() {
            break; // receiver went away
        }
    }
    drop(tx);
    let reply = client.client_stream("/echo.Echo/ClientStream", rx)?;
    println!("ClientStream(words) -> {}", reply.to_str()?);
    assert_eq!(reply.to_str()?, "sum=20");

    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for i in 0..5 {
            if tx.send(Ok(Bytes::from(format!("req-{i}")))).is_err() {
                break;
            }
        }
    });
    let mut stream = client.bidi_stream("/echo.Echo/Bidi", rx)?;
    let mut echoes = Vec::new();
    while let Some(msg) = stream.next_message()? {
        echoes.push(msg.to_str()?.to_string());
    }
    println!("Bidi(req-0..4) -> {echoes:?}");
    assert_eq!(
        echoes,
        [
            "echo:req-0",
            "echo:req-1",
            "echo:req-2",
            "echo:req-3",
            "echo:req-4"
        ]
    );

    let deadline_client = GrpcClient::with_config(GrpcClientConfig {
        base: format!("http://{addr}"),
        max_message_size: courierust::courierust_grpc::DEFAULT_MAX_MESSAGE_SIZE,
        interceptor: None,
        timeout: Some(Duration::from_millis(50)),
        compress: false,
        http_client: h2_client(),
    })?;
    let err = deadline_client
        .call("/echo.Echo/Slow", Bytes::from_static(b"x"))
        .map(|_| ())
        .expect_err("a call that outlives grpc-timeout must be DEADLINE_EXCEEDED");
    assert_eq!(err.grpc_code(), Some(DEADLINE_EXCEEDED));
    println!("Slow with 50 ms deadline -> {err}");

    let gzip_client = GrpcClient::with_config(GrpcClientConfig {
        base: format!("http://{addr}"),
        max_message_size: courierust::courierust_grpc::DEFAULT_MAX_MESSAGE_SIZE,
        interceptor: None,
        timeout: None,
        compress: true,
        http_client: h2_client(),
    })?;
    let mut stream = gzip_client.call_stream("/echo.Echo/ServerStream", Bytes::from("3"))?;
    let negotiated = stream
        .response_headers()
        .get("grpc-encoding")
        .map(|v| v.to_str().unwrap_or(""))
        .unwrap_or("identity")
        .to_string();
    let mut compressed_parts = Vec::new();
    while let Some(msg) = stream.next_message()? {
        compressed_parts.push(msg.to_str()?.to_string());
    }
    println!("gzip client -> grpc-encoding={negotiated}, parts={compressed_parts:?}");
    assert_eq!(negotiated, "gzip", "server must negotiate gzip");
    assert_eq!(compressed_parts, ["part-0", "part-1", "part-2"]);

    let fired = Arc::new(AtomicUsize::new(0));
    let fired2 = fired.clone();
    let interceptor: Arc<dyn courierust::courierust_grpc::Interceptor> =
        Arc::new(move |_method: &str, headers: &mut HeaderMap| {
            fired2.fetch_add(1, Ordering::SeqCst);
            headers.insert(
                HeaderName::from_lowercase("authorization"),
                HeaderValue::from_static("Bearer demo-token"),
            );
        });
    let auth_client = GrpcClient::with_config(GrpcClientConfig {
        base: format!("http://{addr}"),
        max_message_size: courierust::courierust_grpc::DEFAULT_MAX_MESSAGE_SIZE,
        interceptor: Some(interceptor),
        timeout: None,
        compress: false,
        http_client: h2_client(),
    })?;
    let reply = auth_client.call("/echo.Echo/ClientStream", Bytes::from_static(b"m"))?;
    println!(
        "interceptor fired {}/1 call; reply -> {}",
        fired.load(Ordering::SeqCst),
        reply.to_str()?
    );
    assert!(
        fired.load(Ordering::SeqCst) >= 1,
        "interceptor must run per call"
    );

    let mut metadata = HeaderMap::new();
    metadata.insert(
        HeaderName::from_lowercase("x-trace-id"),
        HeaderValue::from_static("trace-42"),
    );
    let mut stream =
        auth_client.call_with_metadata("/echo.Echo/ServerStream", Bytes::from("2"), &metadata)?;
    let mut tagged = Vec::new();
    while let Some(msg) = stream.next_message()? {
        tagged.push(msg.to_str()?.to_string());
    }
    println!(
        "call_with_metadata(x-trace-id) -> {tagged:?}, interceptor fired {} times",
        fired.load(Ordering::SeqCst)
    );
    assert_eq!(tagged, ["part-0", "part-1"]);

    println!("all gRPC streaming paths verified");
    Ok(())
}

/// A plain h2 client for gRPC transports (h2c prior knowledge).
fn h2_client() -> Client {
    Client::with_config(ClientConfig {
        http2: true,
        user_agent: None,
        ..Default::default()
    })
}
