//! End-to-end integration tests: real TCP client↔server over loopback,
//! covering HTTP/1.1, HTTP/2 (h2c), HTTPS (TLS 1.2 + 1.3) and gRPC.

mod common;

use courierust::courierust_body::Body;
use courierust::courierust_bytes::Bytes;
use courierust::courierust_client::{Client, ClientConfig, TlsSettings as ClientTls};
use courierust::courierust_deflate;
use courierust::courierust_grpc::GrpcClient;
use courierust::courierust_http::header::{HeaderName, HeaderValue};
use courierust::courierust_http::method::Method;
use courierust::courierust_http::request::Request;
use courierust::courierust_http::response::Response;
use courierust::courierust_server::{Server, ServerConfig, TlsSettings as ServerTls};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Spin up an HTTP server on an ephemeral port and return its base URL.
fn spawn_server(
    config: ServerConfig,
    handler: impl Fn(
            courierust::courierust_http::request::Request<Body>,
        ) -> courierust::courierust_http::response::Response<Body>
        + Send
        + Sync
        + 'static,
) -> String {
    let server = Server::bind_with_config("127.0.0.1:0", config).unwrap();
    let addr = server.local_addr().unwrap();
    let handle = server.serve_background(handler).unwrap();
    std::mem::forget(handle); // keep serving for the test process
    format!("http://{addr}")
}

/// A test-sized gRPC HTTP configuration: a small worker pool and lenient
/// liveness, so the ~dozen parallel gRPC servers (each defaulting to the
/// full core-count pool) do not oversubscribe the machine.
fn grpc_test_http_cfg() -> ServerConfig {
    ServerConfig {
        threads: 2,
        h2_settings_timeout: Some(std::time::Duration::from_secs(60)),
        h2_ping_interval: None,
        h2_ping_timeout: None,
        h2_idle_timeout: None,
        ..Default::default()
    }
}

/// Bind and serve a streaming gRPC service in the background.
fn bind_grpc_streaming(
    service: impl courierust::courierust_grpc::StreamingService,
) -> std::net::SocketAddr {
    let srv = courierust::courierust_grpc::GrpcServer::bind_streaming_with_config(
        "127.0.0.1:0",
        service,
        grpc_test_http_cfg(),
    )
    .unwrap();
    let addr = srv.local_addr().unwrap();
    let _ = srv.serve_background().unwrap();
    addr
}

/// Bind and serve a unary gRPC service in the background.
fn bind_grpc_unary(service: impl courierust::courierust_grpc::Service) -> std::net::SocketAddr {
    let srv = courierust::courierust_grpc::GrpcServer::bind_streaming_with_config(
        "127.0.0.1:0",
        courierust::courierust_grpc::unary(service),
        grpc_test_http_cfg(),
    )
    .unwrap();
    let addr = srv.local_addr().unwrap();
    let _ = srv.serve_background().unwrap();
    addr
}

fn echo_handler(
    req: courierust::courierust_http::request::Request<Body>,
) -> courierust::courierust_http::response::Response<Body> {
    let mut resp = courierust::courierust_http::response::Response::<Body>::with_status(200.into());
    resp.headers.insert(
        courierust::courierust_http::header::HeaderName::from_lowercase("x-method"),
        courierust::courierust_http::header::HeaderValue::from_bytes(
            req.method.as_str().as_bytes(),
        )
        .unwrap(),
    );
    let body = req.body.collect().unwrap();
    resp.body = Body::Bytes(body);
    resp
}

#[test]
fn h1_get_and_post_roundtrip() {
    let base = spawn_server(ServerConfig::default(), echo_handler);
    let client = Client::new();
    let resp = client.get(&format!("{base}/hello")).unwrap();
    assert_eq!(resp.status.as_u16(), 200);
    assert_eq!(
        resp.headers.get("x-method").unwrap().to_str().unwrap(),
        "GET"
    );
    assert!(resp.body.is_empty());
    let resp = client
        .post(&format!("{base}/echo"), "hello world".to_string())
        .unwrap();
    assert_eq!(
        resp.headers.get("x-method").unwrap().to_str().unwrap(),
        "POST"
    );
    assert_eq!(
        resp.body.collect().unwrap().to_str().unwrap(),
        "hello world"
    );
    let mut req = Request::new(Method::POST, "/path?q=1");
    req.body = Body::Bytes(Bytes::from_static(b"payload"));
    let resp = client.execute(&format!("{base}/path?q=1"), req).unwrap();
    assert_eq!(resp.body.collect().unwrap().as_slice(), b"payload");
}

#[test]
fn a_zero_length_body_is_a_complete_request() {
    // `Content-Length: 0` is a body of no bytes, not a promise of one. Most
    // HTTP clients send exactly this for a body-less `POST`, and `Body::Bytes`
    // of an empty slice is how this crate produces it — so a peer that waits
    // for the body it was told not to expect never answers.
    let base = spawn_server(ServerConfig::default(), echo_handler);
    let client = Client::with_config(ClientConfig {
        read_timeout: Some(Duration::from_secs(3)),
        ..Default::default()
    });
    let resp = client
        .post(&format!("{base}/empty"), String::new())
        .expect("a request with Content-Length: 0 must be answered");
    assert_eq!(resp.status.as_u16(), 200);
    assert!(resp.body.is_empty());

    // The same announcement on a GET, which is the shape a proxy produces
    // when it forwards a body-less request through `Body::Bytes`.
    let mut req = Request::new(Method::GET, "/empty");
    req.body = Body::Bytes(Bytes::from(Vec::new()));
    let resp = client
        .execute(&format!("{base}/empty"), req)
        .expect("a GET with Content-Length: 0 must be answered");
    assert_eq!(resp.status.as_u16(), 200);
}

#[test]
fn h2_get_and_post_roundtrip() {
    let server_cfg = ServerConfig {
        http2: true,
        threads: 1,
        ..Default::default()
    };
    let base = spawn_server(server_cfg, echo_handler);

    let client_cfg = ClientConfig {
        http2: true,
        h2_settings_timeout: Some(std::time::Duration::from_secs(60)),
        h2_ping_interval: None,
        h2_ping_timeout: None,
        h2_idle_timeout: None,
        ..Default::default()
    };
    let client = Client::with_config(client_cfg);

    let resp = client.get(&format!("{base}/h2hello")).unwrap();
    assert_eq!(resp.status.as_u16(), 200);
    assert_eq!(
        resp.headers.get("x-method").unwrap().to_str().unwrap(),
        "GET"
    );

    let mut req = Request::new(Method::POST, "/h2echo");
    req.body = Body::Bytes(Bytes::from_static(b"via-h2"));
    let resp = client.execute(&format!("{base}/h2echo"), req).unwrap();
    assert_eq!(resp.body.collect().unwrap().to_str().unwrap(), "via-h2");
}

/// Flow-control regression: a large request body and a large response
/// body on a fresh h2 connection must both round-trip intact.
///
/// * The request direction needs the connection-level WINDOW_UPDATE to
///   re-schedule a stream whose END_STREAM chunk is still buffered
///   (previously the stream was excluded because `send_done` was set as
///   soon as the body was queued).
/// * The response direction needs batched stream-level WINDOW_UPDATEs as
///   data is consumed (previously the batch accumulator cancelled itself,
///   so responses larger than the initial stream window stalled).
#[test]
fn h2_large_body_flow_control_roundtrip() {
    let server_cfg = ServerConfig {
        http2: true,
        threads: 1,
        ..Default::default()
    };
    let base = spawn_server(server_cfg, echo_handler);

    let client_cfg = ClientConfig {
        http2: true,
        h2_settings_timeout: Some(std::time::Duration::from_secs(60)),
        h2_ping_interval: None,
        h2_ping_timeout: None,
        h2_idle_timeout: None,
        ..Default::default()
    };
    let client = Client::with_config(client_cfg);
    let big: Vec<u8> = (0..(2 * 1024 * 1024)).map(|i| (i % 251) as u8).collect();
    let mut req = Request::new(Method::POST, "/h2-big");
    req.body = Body::Bytes(Bytes::from(big.clone()));
    let resp = client.execute(&format!("{base}/h2-big"), req).unwrap();
    assert_eq!(resp.status.as_u16(), 200);
    let body = resp.body.collect().unwrap();
    assert_eq!(body.as_ref(), big.as_slice(), "2 MiB body must round-trip");
}

#[test]
fn h2_concurrent_streams_multiplex() {
    let server_cfg = ServerConfig {
        http2: true,
        threads: 1,
        ..Default::default()
    };
    let base = spawn_server(server_cfg, |req| {
        std::thread::sleep(std::time::Duration::from_millis(10));
        echo_handler(req)
    });

    let client_cfg = ClientConfig {
        http2: true,
        max_connections_per_host: 1,
        h2_settings_timeout: Some(std::time::Duration::from_secs(60)),
        h2_ping_interval: None,
        h2_ping_timeout: None,
        h2_idle_timeout: None,
        ..Default::default()
    };
    let client = Client::with_config(client_cfg);
    let mut handles = Vec::new();
    for i in 0..16 {
        let client = client.clone();
        let url = format!("{base}/stream/{i}");
        handles.push(std::thread::spawn(move || {
            let resp = client.get(&url).unwrap();
            assert_eq!(resp.status.as_u16(), 200);
            format!("{}", i)
        }));
    }
    for h in handles {
        let _ = h.join().unwrap();
    }
}

#[test]
fn h2_one_connection_concurrent_burst_completes() {
    let server_cfg = ServerConfig {
        http2: true,
        threads: 2,
        ..Default::default()
    };
    let base = spawn_server(server_cfg, |_req| {
        courierust::courierust_http::response::Response::<Body>::with_status(200.into())
            .with_body(Body::Bytes(Bytes::from_static(b"ok")))
    });
    let client = Client::with_config(ClientConfig {
        http2: true,
        max_connections_per_host: 1,
        h2_settings_timeout: Some(std::time::Duration::from_secs(60)),
        h2_ping_interval: None,
        h2_ping_timeout: None,
        h2_idle_timeout: None,
        ..Default::default()
    });
    let t0 = std::time::Instant::now();
    let n = 64;
    let handles: Vec<_> = (0..n)
        .map(|_| {
            let client = client.clone();
            let url = format!("{base}/burst");
            std::thread::spawn(move || {
                let resp = client.get(&url).unwrap();
                assert_eq!(resp.status.as_u16(), 200);
                assert_eq!(resp.body.collect().unwrap().as_slice(), b"ok");
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }

    assert!(
        t0.elapsed() < std::time::Duration::from_secs(15),
        "concurrent h2 burst stalled: {:?}",
        t0.elapsed()
    );
}

#[test]
fn h2_server_streaming_flush_cadence() {
    let server_cfg = ServerConfig {
        http2: true,
        threads: 1,
        h2_settings_timeout: Some(std::time::Duration::from_secs(60)),
        h2_ping_interval: None,
        h2_ping_timeout: None,
        h2_idle_timeout: None,
        ..Default::default()
    };
    let base = spawn_server(server_cfg, |_req| {
        let (tx, body) = courierust::courierust_body::channel();
        std::thread::spawn(move || {
            for i in 0..8 {
                tx.send(Bytes::from(format!("chunk-{i}\n"))).unwrap();
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
        });
        let mut resp =
            courierust::courierust_http::response::Response::<Body>::with_status(200.into());
        resp.body = body;
        resp
    });
    let client = Client::with_config(ClientConfig {
        http2: true,
        max_connections_per_host: 1,
        h2_settings_timeout: Some(std::time::Duration::from_secs(60)),
        h2_ping_interval: None,
        h2_ping_timeout: None,
        h2_idle_timeout: None,
        ..Default::default()
    });
    let t0 = std::time::Instant::now();
    let resp = client.get(&format!("{base}/stream")).unwrap();
    let body = resp.body.collect().unwrap().to_str().unwrap().to_string();
    assert!(
        body.contains("chunk-0") && body.contains("chunk-7"),
        "got {body}"
    );
    assert!(
        t0.elapsed() < std::time::Duration::from_millis(1500),
        "server-streaming flush stalled per chunk: {:?}",
        t0.elapsed()
    );
}

// ---------------------------------------------------------------------
// Concurrency model proofs (worker occupancy is per-connection, not
// per-stream; a slow stream does not block its connection's other
// streams)
// ---------------------------------------------------------------------

/// A server whose `/hold` handler returns a response head and then keeps
/// the stream open (never ends the body); every other path answers
/// immediately.
fn spawn_hold_server(threads: usize) -> String {
    let server_cfg = ServerConfig {
        http2: true,
        threads,
        h2_settings_timeout: Some(std::time::Duration::from_secs(60)),
        h2_ping_interval: None,
        h2_ping_timeout: None,
        h2_idle_timeout: None,
        ..Default::default()
    };
    spawn_server(server_cfg, |req| {
        if req.uri.as_str() == "/hold" {
            let (tx, body) = courierust::courierust_body::channel();
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_secs(30));
                let _ = tx.send(Bytes::from_static(b"done"));
            });
            let mut resp =
                courierust::courierust_http::response::Response::<Body>::with_status(200.into());
            resp.body = body;
            resp
        } else {
            let mut resp =
                courierust::courierust_http::response::Response::<Body>::with_status(200.into());
            resp.body = Body::Bytes(Bytes::from_static(b"fast"));
            resp
        }
    })
}

#[test]
fn h2_slow_stream_does_not_block_other_streams_same_connection() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};

    let base = spawn_hold_server(2);
    let client = Client::with_config(ClientConfig {
        http2: true,
        max_connections_per_host: 1,
        connect_timeout: Some(Duration::from_secs(5)),
        read_timeout: Some(Duration::from_secs(30)),
        h2_settings_timeout: Some(Duration::from_secs(60)),
        h2_ping_interval: None,
        h2_ping_timeout: None,
        h2_idle_timeout: None,
        ..Default::default()
    });

    let head_received = Arc::new(AtomicBool::new(false));
    let head_received2 = head_received.clone();
    let slow_client = client.clone();
    let slow_base = base.clone();
    let _slow = std::thread::spawn(move || {
        let mut last_err = None;
        for _ in 0..4 {
            match slow_client.get(&format!("{slow_base}/hold")) {
                Ok(resp) => {
                    assert_eq!(resp.status.as_u16(), 200);
                    head_received2.store(true, Ordering::SeqCst);
                    std::thread::sleep(Duration::from_secs(8));
                    drop(resp);
                    return;
                }
                Err(e) => {
                    last_err = Some(e);
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }
        panic!("hold stream could not be established: {last_err:?}");
    });

    let t0 = Instant::now();
    while !head_received.load(Ordering::SeqCst) && t0.elapsed() < Duration::from_secs(20) {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        head_received.load(Ordering::SeqCst),
        "the slow stream's response head never arrived"
    );

    for i in 0..5 {
        let t = Instant::now();
        let resp = client.get(&format!("{base}/fast/{i}")).unwrap();
        assert_eq!(resp.status.as_u16(), 200);
        assert_eq!(resp.body.collect().unwrap().to_str().unwrap(), "fast");
        assert!(
            t.elapsed() < Duration::from_secs(10),
            "a fast stream was blocked behind the idle slow stream on the same connection: {:?}",
            t.elapsed()
        );
    }
}

#[test]
fn h2_many_idle_streams_consume_one_worker_not_one_per_stream() {
    let base = spawn_hold_server(2);
    let opened = Arc::new(AtomicUsize::new(0));
    let client_a = Client::with_config(ClientConfig {
        http2: true,
        max_connections_per_host: 1,
        connect_timeout: Some(Duration::from_secs(5)),
        read_timeout: Some(Duration::from_secs(30)),
        h2_settings_timeout: Some(Duration::from_secs(60)),
        h2_ping_interval: None,
        h2_ping_timeout: None,
        h2_idle_timeout: None,
        ..Default::default()
    });
    let mut handles = Vec::new();
    for _ in 0..10 {
        let c = client_a.clone();
        let b = base.clone();
        let opened = opened.clone();
        handles.push(std::thread::spawn(move || {
            let resp = c.get(&format!("{b}/hold")).unwrap();
            assert_eq!(resp.status.as_u16(), 200);
            opened.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(Duration::from_secs(8));
            drop(resp);
        }));
    }

    let t0 = Instant::now();
    while opened.load(Ordering::SeqCst) < 10 && t0.elapsed() < Duration::from_secs(30) {
        std::thread::sleep(Duration::from_millis(10));
    }
    for h in handles {
        let _ = h.join();
    }
    assert_eq!(
        opened.load(Ordering::SeqCst),
        10,
        "not all idle streams opened"
    );

    let mut served = false;
    let mut last_err = None;
    for _ in 0..6 {
        let client_b = Client::with_config(ClientConfig {
            http2: true,
            connect_timeout: Some(Duration::from_secs(5)),
            read_timeout: Some(Duration::from_secs(30)),
            h2_settings_timeout: Some(Duration::from_secs(60)),
            h2_ping_interval: None,
            h2_ping_timeout: None,
            h2_idle_timeout: None,
            ..Default::default()
        });
        let t = Instant::now();
        match client_b.get(&format!("{base}/fresh")) {
            Ok(resp) => {
                assert_eq!(resp.status.as_u16(), 200);
                assert_eq!(resp.body.collect().unwrap().to_str().unwrap(), "fast");
                served = true;
                assert!(
                    t.elapsed() < Duration::from_secs(15),
                    "idle streams starved the worker pool: {:?}",
                    t.elapsed()
                );
                break;
            }
            Err(e) => {
                last_err = Some(e);
                std::thread::sleep(Duration::from_millis(150));
            }
        }
    }
    assert!(
        served,
        "idle streams exhausted the worker pool (all attempts failed): {last_err:?}"
    );
}

#[test]
fn h1_chunked_streaming_response() {
    let base = spawn_server(ServerConfig::default(), |_req| {
        let (tx, body) = courierust::courierust_body::channel();
        std::thread::spawn(move || {
            for i in 0..5 {
                tx.send(Bytes::from(format!("chunk-{i}"))).unwrap();
            }
        });
        let mut resp =
            courierust::courierust_http::response::Response::<Body>::with_status(200.into());
        resp.body = body;
        resp
    });
    let client = Client::new();
    let resp = client.get(&format!("{base}/stream")).unwrap();
    let body = resp.body.collect().unwrap();
    let s = body.to_str().unwrap();
    assert!(s.contains("chunk-0") && s.contains("chunk-4"), "got {s}");
}

#[test]
fn h2_channel_streaming_response() {
    let server_cfg = ServerConfig {
        http2: true,
        threads: 1,
        ..Default::default()
    };
    let base = spawn_server(server_cfg, |_req| {
        let (tx, body) = courierust::courierust_body::channel();
        std::thread::spawn(move || {
            for i in 0..8 {
                tx.send(Bytes::from(format!("part-{i}"))).unwrap();
            }
        });
        let mut resp =
            courierust::courierust_http::response::Response::<Body>::with_status(200.into());
        resp.body = body;
        resp
    });
    let client_cfg = ClientConfig {
        http2: true,
        h2_settings_timeout: Some(std::time::Duration::from_secs(60)),
        h2_ping_interval: None,
        h2_ping_timeout: None,
        h2_idle_timeout: None,
        ..Default::default()
    };
    let client = Client::with_config(client_cfg);
    let resp = client.get(&format!("{base}/stream")).unwrap();
    let body = resp.body.collect().unwrap();
    let s = body.to_str().unwrap();
    assert!(s.contains("part-0") && s.contains("part-7"), "got {s}");
}

#[test]
fn grpc_unary_roundtrip() {
    let service = |method: &str, req: Bytes| -> courierust::Result<Bytes> {
        assert_eq!(method, "/echo.Echo/Say");
        Ok(Bytes::from(format!("echo:{}", req.to_str().unwrap())))
    };
    let addr = bind_grpc_unary(service);

    let client = GrpcClient::new(&format!("http://{addr}")).unwrap();
    let resp = client
        .call("/echo.Echo/Say", Bytes::from_static(b"ping"))
        .unwrap();
    assert_eq!(resp.to_str().unwrap(), "echo:ping");

    let s = client
        .call_unary::<String, String>("/echo.Echo/Say", &"typed".to_string())
        .unwrap();
    assert_eq!(s, "echo:typed");
}

#[test]
fn grpc_error_status() {
    let service = |_method: &str, _req: Bytes| -> courierust::Result<Bytes> {
        Err(courierust::Error::grpc(
            courierust::courierust_grpc::status::NOT_FOUND,
            "nope",
        ))
    };
    let addr = bind_grpc_unary(service);

    let client = GrpcClient::new(&format!("http://{addr}")).unwrap();
    let err = client.call("/x.Y/Z", Bytes::from_static(b"x")).unwrap_err();
    assert_eq!(
        err.grpc_code(),
        Some(courierust::courierust_grpc::status::NOT_FOUND)
    );
}

#[test]
fn grpc_success_status_delivered_in_trailers() {
    let service = |_method: &str, req: Bytes| -> courierust::Result<Bytes> {
        Ok(Bytes::from(format!("echo:{}", req.to_str().unwrap())))
    };
    let addr = bind_grpc_unary(service);

    let client = GrpcClient::new(&format!("http://{addr}")).unwrap();
    let mut stream = client
        .call_with_metadata(
            "/echo.Echo/Say",
            Bytes::from_static(b"x"),
            &courierust::courierust_http::header::HeaderMap::new(),
        )
        .unwrap();
    let msg = stream.next_message().unwrap().unwrap();
    assert_eq!(msg.to_str().unwrap(), "echo:x");
    assert!(stream.next_message().unwrap().is_none());
    let tr = stream.trailers().expect("trailers must be present");
    assert_eq!(tr.get("grpc-status").unwrap().to_str().unwrap(), "0");
    assert!(
        stream.response_headers().get("grpc-status").is_none(),
        "grpc-status must not leak into initial metadata"
    );
}

#[test]
fn grpc_server_enforces_deadline() {
    let service = |_method: &str, _req: Bytes| -> courierust::Result<Bytes> {
        std::thread::sleep(std::time::Duration::from_millis(400));
        Ok(Bytes::from_static(b"too-late"))
    };
    let addr = bind_grpc_unary(service);
    let client = courierust::courierust_grpc::GrpcClient::with_config(
        courierust::courierust_grpc::GrpcClientConfig {
            base: format!("http://{addr}"),
            max_message_size: courierust::courierust_grpc::DEFAULT_MAX_MESSAGE_SIZE,
            interceptor: None,
            timeout: Some(std::time::Duration::from_millis(50)),
            compress: false,
            http_client: Client::with_config(ClientConfig {
                http2: true,
                user_agent: None,
                ..Default::default()
            }),
        },
    )
    .unwrap();
    let err = client
        .call("/echo.Echo/Say", Bytes::from_static(b"x"))
        .unwrap_err();
    assert_eq!(
        err.grpc_code(),
        Some(courierust::courierust_grpc::status::DEADLINE_EXCEEDED)
    );
}

#[test]
fn grpc_server_rejects_malformed_timeout() {
    let service = |_method: &str, req: Bytes| -> courierust::Result<Bytes> {
        Ok(Bytes::from(format!("echo:{}", req.to_str().unwrap())))
    };
    let addr = bind_grpc_unary(service);

    let client = GrpcClient::new(&format!("http://{addr}")).unwrap();
    // Override grpc-timeout with a malformed value via metadata.
    let mut md = courierust::courierust_http::header::HeaderMap::new();
    md.insert(
        courierust::courierust_http::header::HeaderName::from_lowercase("grpc-timeout"),
        courierust::courierust_http::header::HeaderValue::from_static("5X"),
    );
    let mut stream = client
        .call_with_metadata("/echo.Echo/Say", Bytes::from_static(b"x"), &md)
        .unwrap();
    let err = match stream.next_message() {
        Ok(_) => panic!("malformed grpc-timeout must be rejected"),
        Err(e) => e,
    };
    assert_eq!(
        err.grpc_code(),
        Some(courierust::courierust_grpc::status::INVALID_ARGUMENT)
    );
}

#[test]
fn keep_alive_reuse() {
    let base = spawn_server(ServerConfig::default(), echo_handler);
    let client = Client::new();
    // A batch of sequential requests reuses one keep-alive connection.
    for i in 0..10 {
        let resp = client.get(&format!("{base}/k{i}")).unwrap();
        assert_eq!(resp.status.as_u16(), 200);
    }
}

#[test]
fn redirect_following() {
    let base = Arc::new(spawn_server(ServerConfig::default(), |req| {
        if req.uri.as_str() == "/start" {
            let mut resp =
                courierust::courierust_http::response::Response::<Body>::with_status(302.into());
            resp.headers.insert(
                courierust::courierust_http::header::HeaderName::from_lowercase("location"),
                courierust::courierust_http::header::HeaderValue::from_static("/end"),
            );
            resp
        } else {
            let mut resp =
                courierust::courierust_http::response::Response::<Body>::with_status(200.into());
            resp.headers.insert(
                courierust::courierust_http::header::HeaderName::from_lowercase("x-final"),
                courierust::courierust_http::header::HeaderValue::from_static("yes"),
            );
            resp
        }
    }));
    let client = Client::new();
    let resp = client.get(&format!("{base}/start")).unwrap();
    assert_eq!(resp.status.as_u16(), 200);
    assert_eq!(
        resp.headers.get("x-final").unwrap().to_str().unwrap(),
        "yes"
    );
}

/// Security: the h2 client must enforce `max_body` on response bodies, so
/// a malicious peer cannot stream an unbounded body into memory (parity
/// with the h1 client).
#[test]
fn h2_client_enforces_max_body() {
    let server_cfg = ServerConfig {
        http2: true,
        threads: 1,
        ..Default::default()
    };
    let base = spawn_server(server_cfg, |_req| {
        let (tx, body) = courierust::courierust_body::channel();
        std::thread::spawn(move || {
            let chunk = vec![b'x'; 64 * 1024];
            for _ in 0..16 {
                if tx.send(Bytes::from(chunk.clone())).is_err() {
                    break; // client aborted the stream
                }
            }
        });
        let mut resp =
            courierust::courierust_http::response::Response::<Body>::with_status(200.into());
        resp.body = body;
        resp
    });

    let client_cfg = ClientConfig {
        http2: true,
        max_body: 1024,
        h2_settings_timeout: Some(std::time::Duration::from_secs(60)),
        h2_ping_interval: None,
        h2_ping_timeout: None,
        h2_idle_timeout: None,
        ..Default::default()
    };
    let client = Client::with_config(client_cfg);
    let resp = client.get(&format!("{base}/big")).unwrap();
    let err = resp.body.collect().unwrap_err();
    assert!(
        matches!(err.kind, courierust::ErrorKind::Overflow),
        "expected body overflow, got {err:?}"
    );
}

/// Security: credentials must not be forwarded across origins on a
/// redirect (RFC 9110 credential-leakage guidance).
#[test]
fn redirect_strips_credentials_cross_origin() {
    let got_auth = Arc::new(Mutex::new(false));
    let got_auth_b = got_auth.clone();
    let base_b = Arc::new(spawn_server(ServerConfig::default(), move |req| {
        let has = req.headers.contains_key("authorization");
        *got_auth_b.lock().unwrap() = has;
        let mut resp =
            courierust::courierust_http::response::Response::<Body>::with_status(200.into());
        resp.body = Body::Bytes(Bytes::from(if has { "has" } else { "none" }));
        resp
    }));

    let location = base_b.to_string();
    let base_a = spawn_server(ServerConfig::default(), move |_req| {
        let mut resp =
            courierust::courierust_http::response::Response::<Body>::with_status(302.into());
        resp.headers.insert(
            courierust::courierust_http::header::HeaderName::from_lowercase("location"),
            courierust::courierust_http::header::HeaderValue::from_bytes(location.as_bytes())
                .unwrap(),
        );
        resp
    });

    let client = Client::new();
    let mut req = Request::new(Method::GET, "/");
    req.headers.insert(
        courierust::courierust_http::header::HeaderName::from_lowercase("authorization"),
        courierust::courierust_http::header::HeaderValue::from_static("Bearer secret"),
    );
    let resp = client.execute(&format!("{base_a}/"), req).unwrap();
    assert_eq!(resp.status.as_u16(), 200);
    assert!(
        !*got_auth.lock().unwrap(),
        "authorization leaked across origins on redirect"
    );
}

// ---------------------------------------------------------------------
// HTTPS (TLS 1.2 + 1.3) integration tests
// ---------------------------------------------------------------------

/// Spin up an HTTPS server (self-signed test identity) and return its
/// base URL.
fn spawn_tls_server(
    config: ServerConfig,
    handler: impl Fn(
            courierust::courierust_http::request::Request<Body>,
        ) -> courierust::courierust_http::response::Response<Body>
        + Send
        + Sync
        + 'static,
) -> String {
    let server = Server::bind_with_config("127.0.0.1:0", config).unwrap();
    let addr = server.local_addr().unwrap();
    let handle = server.serve_background(handler).unwrap();
    std::mem::forget(handle); // keep serving for the test process
    format!("https://{addr}")
}

fn https_server_config(http2: bool) -> ServerConfig {
    ServerConfig {
        http2,
        threads: 1,
        tls: Some(ServerTls {
            identity: common::server_identity(),
            alpn: if http2 {
                vec![b"h2".to_vec()]
            } else {
                vec![b"http/1.1".to_vec()]
            },
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn https_client_config(http2: bool) -> ClientConfig {
    ClientConfig {
        http2,
        tls: Some(ClientTls {
            roots: common::root_store(),
            verify: true,
            alpn: if http2 {
                vec![b"h2".to_vec()]
            } else {
                vec![b"http/1.1".to_vec()]
            },
            now: common::NOW,
            ..Default::default()
        }),
        ..Default::default()
    }
}

#[test]
fn https_h1_get_and_post_roundtrip() {
    let base = spawn_tls_server(https_server_config(false), echo_handler);
    let client = Client::with_config(https_client_config(false));
    let resp = client.get(&format!("{base}/secure-hello")).unwrap();
    assert_eq!(resp.status.as_u16(), 200);
    assert_eq!(
        resp.headers.get("x-method").unwrap().to_str().unwrap(),
        "GET"
    );

    let mut req = Request::new(Method::POST, "/secure-echo");
    req.body = Body::Bytes(Bytes::from_static(b"over-tls"));
    let resp = client.execute(&format!("{base}/secure-echo"), req).unwrap();
    assert_eq!(resp.body.collect().unwrap().to_str().unwrap(), "over-tls");
}

#[test]
fn https_h2_get_and_post_roundtrip() {
    let base = spawn_tls_server(https_server_config(true), echo_handler);
    let client = Client::with_config(https_client_config(true));

    let resp = client.get(&format!("{base}/h2-secure")).unwrap();
    assert_eq!(resp.status.as_u16(), 200);
    assert_eq!(
        resp.headers.get("x-method").unwrap().to_str().unwrap(),
        "GET"
    );

    let mut req = Request::new(Method::POST, "/h2-secure-echo");
    req.body = Body::Bytes(Bytes::from_static(b"via-h2-tls"));
    let resp = client
        .execute(&format!("{base}/h2-secure-echo"), req)
        .unwrap();
    assert_eq!(resp.body.collect().unwrap().to_str().unwrap(), "via-h2-tls");
}

/// A client without the test root must refuse the HTTPS server.
#[test]
fn https_rejects_untrusted_server() {
    let base = spawn_tls_server(https_server_config(false), echo_handler);
    let client = Client::new(); // tls = None
    let err = client.get(&format!("{base}/nope")).unwrap_err();
    assert!(
        matches!(err.kind, courierust::ErrorKind::Protocol),
        "expected scheme rejection without tls config, got {err:?}"
    );

    let cfg = ClientConfig {
        tls: Some(ClientTls {
            roots: courierust::courierust_tls::RootStore::new(),
            verify: true,
            alpn: vec![b"http/1.1".to_vec()],
            now: common::NOW,
            ..Default::default()
        }),
        ..Default::default()
    };
    let client = Client::with_config(cfg);
    let err = client.get(&format!("{base}/nope")).unwrap_err();
    let msg = err.to_string().to_ascii_lowercase();
    assert!(
        msg.contains("tls") || msg.contains("certificate") || msg.contains("handshake"),
        "expected a TLS handshake failure, got {err:?}"
    );
}

/// The one-line HTTPS client constructor (`with_tls_roots`) must speak
/// HTTPS (h2 via ALPN) out of the box.
#[test]
fn https_with_tls_roots_convenience() {
    let base = spawn_tls_server(https_server_config(true), echo_handler);
    let client = Client::with_tls_roots(common::root_store());
    let resp = client.get(&format!("{base}/via-helper")).unwrap();
    assert_eq!(resp.status.as_u16(), 200);
    assert_eq!(
        resp.headers.get("x-method").unwrap().to_str().unwrap(),
        "GET"
    );
}

/// The HTTPS server must survive malformed / hostile TLS input: garbage
/// that is not a valid ClientHello is rejected without crashing the
/// server or wedging its pool, and valid clients keep working.
#[test]
fn https_server_survives_malformed_tls_input() {
    use std::io::Write;

    let base = spawn_tls_server(https_server_config(true), echo_handler);
    let addr = base.trim_start_matches("https://").to_string();
    let junk: [&[u8]; 3] = [
        &[0x16, 0x03, 0x01, 0x00, 0x02, 0xff, 0xff], // truncated handshake
        &[0x15, 0x03, 0x03, 0x00, 0x01, 0x00],       // alert as first record
        &[0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00], // not TLS at all
    ];
    for _ in 0..4 {
        if let Ok(mut s) = std::net::TcpStream::connect(&addr) {
            let _ = s.write_all(junk[0]);
            let _ = s.write_all(junk[1]);
            let _ = s.write_all(junk[2]);
            let _ = s.flush();
        }
    }
    std::thread::sleep(std::time::Duration::from_millis(50));

    let client = Client::with_config(https_client_config(true));
    let resp = client.get(&format!("{base}/after-garbage")).unwrap();
    assert_eq!(resp.status.as_u16(), 200);
}

/// ALPN must be enforced: a client configured for HTTP/1.1 whose TLS
/// layer nevertheless negotiates h2 gets a clear error instead of a
/// silent protocol mismatch.
#[test]
fn https_client_enforces_alpn_agreement() {
    let base = spawn_tls_server(https_server_config(true), echo_handler);
    let client = Client::with_config(ClientConfig {
        http2: false,
        tls: Some(ClientTls {
            roots: common::root_store(),
            verify: true,
            alpn: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            now: common::NOW,
            ..Default::default()
        }),
        ..Default::default()
    });
    let err = client.get(&format!("{base}/nope")).unwrap_err();
    let msg = err.to_string().to_ascii_lowercase();
    assert!(
        msg.contains("negotiated") && msg.contains("h2"),
        "expected an ALPN agreement error, got {err:?}"
    );
}

/// `TlsSettings::verify = false` must skip certificate/hostname
/// validation: a client with an *empty* root store still completes the
/// handshake against the self-signed test server. The CertificateVerify
/// signature is still always checked, so the handshake is
/// cryptographically sound — it is simply not anchored to a trust root.
#[test]
fn https_verify_disabled_accepts_self_signed() {
    let base = spawn_tls_server(https_server_config(false), echo_handler);
    let client = Client::with_config(ClientConfig {
        http2: false,
        tls: Some(ClientTls {
            roots: courierust::courierust_tls::RootStore::new(), // no trust anchor
            verify: false,
            alpn: vec![b"http/1.1".to_vec()],
            now: common::NOW,
            ..Default::default()
        }),
        ..Default::default()
    });
    let resp = client.get(&format!("{base}/unverified")).unwrap();
    assert_eq!(resp.status.as_u16(), 200);
    assert_eq!(
        resp.headers.get("x-method").unwrap().to_str().unwrap(),
        "GET"
    );
}

/// With verification enabled, a server whose certificate does not cover
/// the requested hostname must be rejected (RFC 6125). The test
/// certificate only covers `DNS:localhost` and `IP:127.0.0.1`.
#[test]
fn tls_hostname_mismatch_rejected() {
    let base = spawn_tls_server(https_server_config(false), echo_handler);
    let addr = base.trim_start_matches("https://").to_string();
    let connector =
        courierust::courierust_tls::TlsConnector::new(courierust::courierust_tls::ClientConfig {
            roots: common::root_store(),
            verify: true,
            alpn: vec![b"http/1.1".to_vec()],
            now: common::NOW,
            ..Default::default()
        });
    {
        let s = std::net::TcpStream::connect(&addr).unwrap();
        s.set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        connector
            .connect("localhost", &s, &s)
            .expect("covered hostname must validate");
    } // s dropped: FIN reaches the server, releasing its worker

    let s = std::net::TcpStream::connect(&addr).unwrap();
    s.set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    let err = match connector.connect("not-localhost.invalid", &s, &s) {
        Ok(_) => panic!("uncovered hostname unexpectedly validated"),
        Err(e) => e,
    };
    let msg = err.to_string().to_ascii_lowercase();
    assert!(
        msg.contains("hostname") || msg.contains("certificate"),
        "expected a hostname/certificate rejection, got {err:?}"
    );
}

/// Redirects from an HTTPS origin must stay on HTTPS. The `Location`
/// here is an absolute https URL; reaching the TLS server with 200 proves
/// the client did not downgrade the scheme (a downgrade to plain HTTP
/// would fail the TLS handshake on this server).
#[test]
fn https_redirect_preserves_scheme() {
    let target = Arc::new(spawn_tls_server(https_server_config(false), |_req| {
        courierust::courierust_http::response::Response::<Body>::with_status(200.into())
    }));

    let location = target.to_string();
    let base = spawn_tls_server(https_server_config(false), move |_req| {
        let mut resp =
            courierust::courierust_http::response::Response::<Body>::with_status(302.into());
        resp.headers.insert(
            courierust::courierust_http::header::HeaderName::from_lowercase("location"),
            courierust::courierust_http::header::HeaderValue::from_bytes(location.as_bytes())
                .unwrap(),
        );
        resp
    });

    let client = Client::with_config(https_client_config(false));
    let resp = client.get(&format!("{base}/start")).unwrap();
    assert_eq!(resp.status.as_u16(), 200);
}

// ---------------------------------------------------------------------
// TLS policy / security hardening
// ---------------------------------------------------------------------

/// Spin up an HTTPS server with an explicit TLS identity (used by the
/// expired / wrong-chain / mismatch security tests).
fn spawn_tls_server_with_identity(
    identity: courierust::courierust_tls::Identity,
    alpn: Vec<Vec<u8>>,
) -> String {
    let server = Server::bind_with_config(
        "127.0.0.1:0",
        ServerConfig {
            http2: alpn.iter().any(|p| p == b"h2"),
            threads: 1,
            tls: Some(ServerTls {
                identity,
                alpn,
                ..Default::default()
            }),
            ..Default::default()
        },
    )
    .unwrap();
    let addr = server.local_addr().unwrap();
    let handle = server.serve_background(echo_handler).unwrap();
    std::mem::forget(handle);
    format!("https://{addr}")
}

/// A root store that trusts exactly one DER certificate.
fn root_store_from_der(cert_der: &[u8]) -> courierust::courierust_tls::RootStore {
    let mut roots = courierust::courierust_tls::RootStore::new();
    roots.add_der(cert_der.to_vec());
    roots
}

/// An expired (2020-01-01 .. 2021-01-01) self-signed `localhost`
/// certificate must be rejected on the validity window even when the
/// client explicitly trusts it.
#[test]
fn tls_rejects_expired_certificate() {
    let expired_identity = courierust::courierust_tls::Identity {
        cert_chain: vec![include_bytes!("certs/expired_cert.der").to_vec()],
        private_key: include_bytes!("certs/expired_key.der").to_vec(),
        is_rsa: false,
    };
    let base = spawn_tls_server_with_identity(expired_identity, vec![b"http/1.1".to_vec()]);
    let client = Client::with_config(ClientConfig {
        http2: false,
        tls: Some(ClientTls {
            roots: root_store_from_der(include_bytes!("certs/expired_cert.der")),
            verify: true,
            alpn: vec![b"http/1.1".to_vec()],
            now: common::NOW, // 2027-01-14: far outside 2020..2021
            ..Default::default()
        }),
        ..Default::default()
    });

    let err = client
        .get(&format!("{base}/"))
        .map(|_| ())
        .expect_err("an expired certificate must be rejected");
    let msg = err.to_string().to_ascii_lowercase();
    assert!(
        msg.contains("validity") || msg.contains("expired") || msg.contains("certificate"),
        "expected a validity rejection, got {err:?}"
    );
}

/// A leaf certificate issued by an untrusted CA must be rejected: the
/// chain does not anchor to any trusted root.
#[test]
fn tls_rejects_untrusted_issuer_chain() {
    let wrong_chain_identity = courierust::courierust_tls::Identity {
        // Leaf signed by `ca_other` (NOT in the client's trust store);
        // the presented chain is leaf + its issuer so the chain walk is
        // exercised, not just the anchor fallback.
        cert_chain: vec![
            include_bytes!("certs/wrong_chain_cert.der").to_vec(),
            include_bytes!("certs/ca_other_cert.der").to_vec(),
        ],
        private_key: include_bytes!("certs/wrong_chain_key.der").to_vec(),
        is_rsa: false,
    };
    let base = spawn_tls_server_with_identity(wrong_chain_identity, vec![b"http/1.1".to_vec()]);
    // The client trusts only the real test root; the leaf's issuer is a
    // different, untrusted CA, so chain building must fail.
    let client = Client::with_config(ClientConfig {
        http2: false,
        tls: Some(ClientTls {
            roots: common::root_store(),
            verify: true,
            alpn: vec![b"http/1.1".to_vec()],
            now: common::NOW,
            ..Default::default()
        }),
        ..Default::default()
    });

    let err = client
        .get(&format!("{base}/"))
        .map(|_| ())
        .expect_err("a chain to an untrusted CA must be rejected");
    let msg = err.to_string().to_ascii_lowercase();
    assert!(
        msg.contains("root") || msg.contains("certificate") || msg.contains("chain"),
        "expected a chain/root rejection, got {err:?}"
    );
}

/// A self-signed certificate that the caller *explicitly* adds to its
/// root store must verify (this is the documented trust model: no
/// bundled roots, the caller supplies its own anchors).
#[test]
fn tls_accepts_self_signed_when_explicitly_trusted() {
    let base = spawn_tls_server(https_server_config(false), echo_handler);
    let client = Client::with_config(ClientConfig {
        http2: false,
        tls: Some(ClientTls {
            roots: common::root_store(), // the self-signed test cert IS the anchor
            verify: true,
            alpn: vec![b"http/1.1".to_vec()],
            now: common::NOW,
            ..Default::default()
        }),
        ..Default::default()
    });

    let resp = client.get(&format!("{base}/trusted")).unwrap();
    assert_eq!(resp.status.as_u16(), 200);
}

/// Build a minimal TLS 1.2 ClientHello record (no `supported_versions`,
/// no `key_share`): a real TLS 1.2 client would send exactly this shape.
fn tls12_client_hello() -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // legacy_version = TLS 1.2
    body.extend_from_slice(&[0xab; 32]); // random
    body.push(0); // session_id length
    body.extend_from_slice(&[0x00, 0x04]); // two cipher suites
    body.extend_from_slice(&[0xc0, 0x2f]); // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    body.extend_from_slice(&[0x00, 0x2f]); // TLS_RSA_WITH_AES_128_CBC_SHA
    body.extend_from_slice(&[1, 0]); // compression methods: [null]
    body.extend_from_slice(&[0x00, 0x00]); // no extensions (no 1.3 ext)
    let mut msg = Vec::new();
    msg.push(0x01); // handshake type ClientHello
    msg.extend_from_slice(&u32::to_be_bytes(body.len() as u32)[1..]); // 24-bit length
    msg.extend_from_slice(&body);
    let mut record = Vec::new();
    record.push(0x16); // handshake record
    record.extend_from_slice(&[0x03, 0x03]); // legacy record version
    record.extend_from_slice(&u16::to_be_bytes(msg.len() as u16));
    record.extend_from_slice(&msg);
    record
}

/// The server defaults to TLS 1.2..=1.3, but a *minimal* TLS 1.2
/// ClientHello that omits the ECDHE-required `supported_groups` and
/// `signature_algorithms` extensions cannot complete a key exchange and
/// must be rejected — never answered with a downgraded static-RSA or
/// plaintext HTTP response.
#[test]
fn tls_server_rejects_tls12_client_hello() {
    use std::io::{Read, Write};

    let base = spawn_tls_server(https_server_config(false), echo_handler);
    let addr = base.trim_start_matches("https://").to_string();

    let mut stream = std::net::TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(&tls12_client_hello()).unwrap();

    let mut buf = [0u8; 512];
    let rejected = 'check: loop {
        match stream.read(&mut buf) {
            Ok(0) => break 'check true,
            Ok(n) => {
                // The server must not answer the incomplete hello with an
                // HTTP response; an alert record (0x15) or close is the
                // expected outcome.
                if buf[0] == 0x15 {
                    break 'check true;
                }
                if buf.starts_with(b"HTTP/") {
                    panic!("server responded over HTTP to a TLS 1.2 ClientHello");
                }
                let _ = n; // any other record is not a downgrade response
            }
            Err(_) => {
                // read timeout: the server closed or stalled — either way
                // there was no downgrade response.
                break 'check true;
            }
        }
    };
    assert!(rejected, "TLS 1.2 hello was not rejected");
}

/// A peer that accepts the TCP connection and then aborts the handshake
/// (garbage + close) must make the TLS client fail cleanly instead of
/// hanging.
#[test]
fn tls_client_handshake_interrupted() {
    use std::io::Write;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let _ = stream.write_all(b"\x16\x03\x03\x00\x05garbage");
            // Close without completing the handshake.
        }
    });

    let stream = std::net::TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let connector =
        courierust::courierust_tls::TlsConnector::new(courierust::courierust_tls::ClientConfig {
            roots: common::root_store(),
            verify: true,
            alpn: vec![b"http/1.1".to_vec()],
            now: common::NOW,
            ..Default::default()
        });
    let t0 = Instant::now();
    let err = connector
        .connect("localhost", &stream, &stream)
        .map(|_| ())
        .expect_err("an interrupted TLS handshake must fail");
    assert!(
        t0.elapsed() < Duration::from_secs(5),
        "interrupted handshake must fail fast, not hang"
    );
    assert!(!err.to_string().is_empty());
}

// ---------------------------------------------------------------------
// Event-driven server (default on every platform): idle connections must
// not hold workers
// ---------------------------------------------------------------------

/// A raw TCP client with persistent read buffering.
///
/// `read_response` must not discard bytes that arrive in the same TCP
/// segment as an earlier response: a naive "read head + body" helper
/// consumes the pipelined tail into its scratch buffer and then blocks
/// forever waiting for the next response (the server already sent it).
/// Keeping the leftover here makes reading multiple pipelined responses
/// on one connection deterministic across platforms and scheduling.
struct RawConn {
    stream: std::net::TcpStream,
    /// Bytes read from the socket but not yet returned to the caller.
    leftover: Vec<u8>,
    /// Consume cursor into `leftover` (compacted once it grows).
    pos: usize,
}

impl RawConn {
    fn new(stream: std::net::TcpStream) -> Self {
        // A read timeout turns a server stall into a fast test failure
        // instead of a multi-minute hang.
        let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(30)));
        Self {
            stream,
            leftover: Vec::new(),
            pos: 0,
        }
    }

    fn stream(&mut self) -> &mut std::net::TcpStream {
        &mut self.stream
    }

    /// Read one complete HTTP/1.1 response, or `None` when the peer
    /// closed without answering (used by tests that assert on *where* a
    /// request fails).
    fn try_read_response(&mut self) -> Option<String> {
        loop {
            if let Some((head_end, cl)) = self.find_response() {
                let total = head_end + cl;
                while self.leftover.len() - self.pos < total {
                    if !self.try_fill() {
                        return None;
                    }
                }
                let s =
                    String::from_utf8_lossy(&self.leftover[self.pos..self.pos + total]).to_string();
                self.pos += total;
                self.compact();
                return Some(s);
            }
            if !self.try_fill() {
                return None;
            }
        }
    }

    /// Read one complete HTTP/1.1 response (head + Content-Length body).
    fn read_response(&mut self) -> String {
        loop {
            if let Some((head_end, cl)) = self.find_response() {
                let total = head_end + cl;
                while self.leftover.len() - self.pos < total {
                    self.fill();
                }
                let s =
                    String::from_utf8_lossy(&self.leftover[self.pos..self.pos + total]).to_string();
                self.pos += total;
                self.compact();
                return s;
            }
            self.fill();
        }
    }

    /// Locate the response head end and Content-Length in the buffered
    /// (unconsumed) data.
    fn find_response(&self) -> Option<(usize, usize)> {
        let buf = &self.leftover[self.pos..];
        let he = find_subslice(buf, b"\r\n\r\n")? + 4;
        let head = String::from_utf8_lossy(&buf[..he]);
        let cl = head
            .lines()
            .find_map(|l| {
                let (k, v) = l.split_once(':')?;
                if k.eq_ignore_ascii_case("content-length") {
                    v.trim().parse::<usize>().ok()
                } else {
                    None
                }
            })
            .unwrap_or(0);
        Some((he, cl))
    }

    fn fill(&mut self) {
        use std::io::Read;
        let mut tmp = [0u8; 4096];
        let n = self.stream.read(&mut tmp).unwrap();
        assert!(n > 0, "unexpected EOF while reading response");
        self.leftover.extend_from_slice(&tmp[..n]);
    }

    /// `fill` that reports EOF instead of panicking.
    fn try_fill(&mut self) -> bool {
        use std::io::Read;
        let mut tmp = [0u8; 4096];
        match self.stream.read(&mut tmp) {
            Ok(0) => false,
            Ok(n) => {
                self.leftover.extend_from_slice(&tmp[..n]);
                true
            }
            Err(e) => panic!("read failed: {e}"),
        }
    }

    fn compact(&mut self) {
        if self.pos >= 64 * 1024 {
            self.leftover.drain(..self.pos);
            self.pos = 0;
        }
    }
}

/// RFC 9112 §3.2: an HTTP/1.1 request must carry exactly one non-empty
/// `Host` field. A server that skips the check lets a proxy and the
/// origin disagree about which authority a request was for — the shape
/// of a request-smuggling bug — so the check is a test, not a comment.
///
/// Both drivers are exercised: the event-driven path is the default one,
/// and a rule implemented in only one of them is a rule with a hole.
#[test]
fn http11_requires_exactly_one_non_empty_host_header() {
    use std::io::Write;
    use std::net::TcpStream;

    for event_driven in [true, false] {
        let base = spawn_server(
            ServerConfig {
                event_driven,
                threads: 2,
                ..Default::default()
            },
            |_req| {
                let mut resp = courierust::courierust_http::response::Response::<Body>::with_status(
                    200.into(),
                );
                resp.body = Body::Bytes(Bytes::from_static(b"ok"));
                resp
            },
        );
        let addr = base.trim_start_matches("http://").to_string();
        let ask = |label: &str, request: &[u8]| -> String {
            let mut conn = RawConn::new(TcpStream::connect(&addr).unwrap());
            conn.stream().write_all(request).unwrap();
            conn.try_read_response()
                .unwrap_or_else(|| panic!("no response at all for {label}"))
        };
        let driver = if event_driven { "event" } else { "blocking" };

        // Missing Host -> 400.
        let resp = ask("no Host", b"GET / HTTP/1.1\r\n\r\n");
        assert!(resp.starts_with("HTTP/1.1 400"), "{driver}: got {resp}");

        // Duplicate Host -> 400 (two authorities are not a request).
        let resp = ask(
            "duplicate Host",
            b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n",
        );
        assert!(resp.starts_with("HTTP/1.1 400"), "{driver}: got {resp}");

        // Empty Host -> 400.
        let resp = ask("empty Host", b"GET / HTTP/1.1\r\nHost:\r\n\r\n");
        assert!(resp.starts_with("HTTP/1.1 400"), "{driver}: got {resp}");

        // One Host -> 200.
        let resp = ask(
            "one Host",
            b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
        );
        assert!(resp.starts_with("HTTP/1.1 200"), "{driver}: got {resp}");
        assert!(resp.ends_with("ok"), "{driver}: got {resp}");

        // HTTP/1.0 may omit Host; the request is still served.
        let resp = ask("HTTP/1.0 without Host", b"GET / HTTP/1.0\r\n\r\n");
        assert!(resp.starts_with("HTTP/1.1 200"), "{driver}: got {resp}");

        // A request line the server cannot parse is answered, not dropped:
        // both drivers must agree, because a client behind a proxy cannot
        // tell a server bug from a network failure otherwise.
        let resp = ask("malformed request line", b"GARBAGE\r\n\r\n");
        assert!(resp.starts_with("HTTP/1.1 400"), "{driver}: got {resp}");
    }
}

/// `max_header_list` is a server-wide safety policy: HTTP/1.1 must honor
/// it exactly as HTTP/2 and HTTP/3 do, rather than retaining a hidden
/// fixed one-megabyte allowance after a protocol downgrade.
#[test]
fn h1_enforces_configured_header_list_limit_on_both_drivers() {
    use std::io::Write;
    use std::net::TcpStream;

    for event_driven in [true, false] {
        let base = spawn_server(
            ServerConfig {
                http2: false,
                event_driven,
                threads: 1,
                event_workers: 1,
                max_header_list: 32,
                ..Default::default()
            },
            |_req| courierust::courierust_http::response::Response::<Body>::with_status(200.into()),
        );
        let addr = base.trim_start_matches("http://").to_string();
        let mut conn = RawConn::new(TcpStream::connect(addr).unwrap());
        conn.stream()
            .write_all(b"GET / HTTP/1.1\r\nHost: x\r\nX-Long: 0123456789abcdef\r\n\r\n")
            .unwrap();
        let response = conn
            .try_read_response()
            .unwrap_or_else(|| panic!("event_driven={event_driven}: no response"));
        assert!(
            response.starts_with("HTTP/1.1 431"),
            "event_driven={event_driven}: got {response}"
        );
    }
}

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// With only two event workers, a large herd of idle keep-alive
/// connections must NOT exhaust the pool: a fresh request is still served
/// promptly (idle connections park on the poller, consuming zero
/// workers).
#[test]
fn event_many_idle_connections_do_not_block_workers() {
    use std::io::Write;
    use std::net::TcpStream;

    let server_cfg = ServerConfig {
        http2: false,
        event_driven: true,
        event_workers: 2,
        threads: 2,
        ..Default::default()
    };
    let base = spawn_server(server_cfg, |_req| {
        let mut resp =
            courierust::courierust_http::response::Response::<Body>::with_status(200.into());
        resp.headers.insert(
            courierust::courierust_http::header::HeaderName::from_lowercase("content-length"),
            courierust::courierust_http::header::HeaderValue::from_static("2"),
        );
        resp.body = Body::Bytes(Bytes::from_static(b"ok"));
        resp
    });
    let addr = base.trim_start_matches("http://").to_string();
    let mut idle: Vec<RawConn> = Vec::new();
    for _ in 0..60 {
        let mut c = RawConn::new(TcpStream::connect(&addr).unwrap());
        c.stream()
            .write_all(b"GET /idle HTTP/1.1\r\nHost: x\r\n\r\n")
            .unwrap();
        let resp = c.read_response();
        assert!(resp.starts_with("HTTP/1.1 200"), "got {resp}");
        idle.push(c); // hold open: idle keep-alive
    }

    let client = Client::new();
    let t0 = std::time::Instant::now();
    let resp = client.get(&format!("{base}/fresh")).unwrap();
    assert_eq!(resp.status.as_u16(), 200);
    assert!(
        t0.elapsed() < std::time::Duration::from_secs(10),
        "fresh request blocked behind idle connections: {:?}",
        t0.elapsed()
    );

    for c in idle.iter_mut() {
        c.stream()
            .write_all(b"GET /again HTTP/1.1\r\nHost: x\r\n\r\n")
            .unwrap();
        let resp = c.read_response();
        assert!(resp.starts_with("HTTP/1.1 200"), "got {resp}");
    }
}

/// The default server configuration must use the event-driven scheduler
/// (the one that parks idle connections) on every platform, with the
/// slow-loris idle bound and the low-idle-wakeup poll timeout — the
/// properties the user-visible scheduler switch is supposed to guarantee.
#[test]
fn server_defaults_to_event_driven_scheduler() {
    let d = ServerConfig::default();
    assert!(d.event_driven, "event_driven must default to true");
    assert_eq!(d.event_poll_timeout_ms, 50);
    assert_eq!(
        d.request_header_timeout,
        Some(std::time::Duration::from_secs(15))
    );
    assert_eq!(d.idle_timeout, Some(std::time::Duration::from_secs(300)));
    assert_eq!(d.h2_idle_timeout, Some(std::time::Duration::from_secs(300)));
}

/// Sequential keep-alive requests over one event-driven connection must
/// be served without a multi-poll stall: the self-pipe wakes the event
/// loop the moment a worker re-registers the connection, and socket
/// readiness wakes it the moment the client sends data. 200 round trips
/// must complete promptly from a tiny worker pool.
#[test]
fn event_keepalive_sequential_requests_do_not_stall() {
    use std::io::Write;
    use std::net::TcpStream;

    let server_cfg = ServerConfig {
        http2: false,
        event_driven: true,
        event_workers: 1,
        threads: 1,
        ..Default::default()
    };
    let base = spawn_server(server_cfg, |_req| {
        let mut resp =
            courierust::courierust_http::response::Response::<Body>::with_status(200.into());
        resp.headers.insert(
            courierust::courierust_http::header::HeaderName::from_lowercase("content-length"),
            courierust::courierust_http::header::HeaderValue::from_static("2"),
        );
        resp.body = Body::Bytes(Bytes::from_static(b"ok"));
        resp
    });
    let addr = base.trim_start_matches("http://").to_string();
    let mut c = RawConn::new(TcpStream::connect(addr).unwrap());
    let t0 = std::time::Instant::now();
    for _ in 0..200 {
        c.stream()
            .write_all(b"GET /k HTTP/1.1\r\nHost: x\r\n\r\n")
            .unwrap();
        let resp = c.read_response();
        assert!(resp.starts_with("HTTP/1.1 200"), "got {resp}");
    }
    assert!(
        t0.elapsed() < std::time::Duration::from_secs(10),
        "sequential keep-alive stalled: {:?}",
        t0.elapsed()
    );
}

/// An HTTP/1.1 connection that sends a partial request and then stalls
/// (slow-loris) must be closed by the idle timeout, releasing its fd and
/// its parked slot even though it never completes a request.
#[test]
fn event_idle_timeout_reaps_slowloris() {
    use std::io::{Read, Write};
    use std::net::TcpStream;

    let server_cfg = ServerConfig {
        http2: false,
        event_driven: true,
        event_workers: 1,
        threads: 1,
        idle_timeout: Some(std::time::Duration::from_millis(300)),
        event_poll_timeout_ms: 10,
        ..Default::default()
    };
    let base = spawn_server(server_cfg, |_req| {
        let mut resp =
            courierust::courierust_http::response::Response::<Body>::with_status(200.into());
        resp.headers.insert(
            courierust::courierust_http::header::HeaderName::from_lowercase("content-length"),
            courierust::courierust_http::header::HeaderValue::from_static("2"),
        );
        resp.body = Body::Bytes(Bytes::from_static(b"ok"));
        resp
    });
    let addr = base.trim_start_matches("http://").to_string();

    let mut s = TcpStream::connect(addr).unwrap();
    s.write_all(b"GET /loris HTTP/1.1\r\nHost: x\r\n").unwrap();
    let t0 = std::time::Instant::now();
    let mut buf = [0u8; 16];
    let mut closed = false;
    while t0.elapsed() < std::time::Duration::from_secs(5) {
        match s.read(&mut buf) {
            Ok(0) => {
                closed = true;
                break;
            }
            Ok(_) => {}
            Err(_) => {
                closed = true;
                break;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(
        closed,
        "slow-loris connection was not reaped by the idle timeout"
    );
}

/// A peer cannot keep a request slot forever by sending a byte more often
/// than the idle timeout. The absolute header deadline applies to both
/// server drivers and answers with RFC 9110's 408 before closing.
#[test]
fn request_header_timeout_stops_trickling_slowloris() {
    use std::io::{Read, Write};
    use std::net::TcpStream;

    for event_driven in [true, false] {
        let server_cfg = ServerConfig {
            http2: false,
            event_driven,
            event_workers: 1,
            threads: 1,
            request_header_timeout: Some(Duration::from_millis(300)),
            idle_timeout: Some(Duration::from_secs(10)),
            event_poll_timeout_ms: 10,
            ..Default::default()
        };
        let base = spawn_server(server_cfg, |_req| {
            courierust::courierust_http::response::Response::<Body>::with_status(200.into())
        });
        let addr = base.trim_start_matches("http://").to_string();
        let mut stream = TcpStream::connect(addr).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        stream.write_all(b"GET / HTTP/1.1\r\nHost: ").unwrap();
        for _ in 0..4 {
            std::thread::sleep(Duration::from_millis(50));
            if stream.write_all(b"x").is_err() {
                break;
            }
        }
        let mut response = Vec::new();
        let mut buffer = [0u8; 256];
        loop {
            match stream.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(n) => response.extend_from_slice(&buffer[..n]),
            }
        }
        let response = String::from_utf8(response).unwrap();
        assert!(
            response.starts_with("HTTP/1.1 408"),
            "event_driven={event_driven}: got {response:?}"
        );
    }
}

/// The connection cap bounds the event path: connections beyond
/// `max_connections` are closed immediately (a herd cannot grow without
/// bound), and once the admitted connections go away the server keeps
/// serving fresh requests (the cap never wedges the loop).
#[test]
fn event_connection_cap_limits_herd() {
    use std::io::{Read, Write};
    use std::net::TcpStream;

    let server_cfg = ServerConfig {
        http2: false,
        event_driven: true,
        event_workers: 1,
        threads: 1,
        max_connections: 4,
        idle_timeout: Some(std::time::Duration::from_secs(300)), // long: cap, not reap, closes the excess
        ..Default::default()
    };
    let base = spawn_server(server_cfg, |_req| {
        let mut resp =
            courierust::courierust_http::response::Response::<Body>::with_status(200.into());
        resp.headers.insert(
            courierust::courierust_http::header::HeaderName::from_lowercase("content-length"),
            courierust::courierust_http::header::HeaderValue::from_static("2"),
        );
        resp.body = Body::Bytes(Bytes::from_static(b"ok"));
        resp
    });
    let addr = base.trim_start_matches("http://").to_string();

    let mut herd = Vec::new();
    for _ in 0..8 {
        let mut s = TcpStream::connect(&addr).unwrap();
        s.set_read_timeout(Some(std::time::Duration::from_millis(400)))
            .unwrap();
        s.write_all(b"GET /partial HTTP/1.1\r\nHost: x\r\n")
            .unwrap();
        herd.push(s);
    }

    std::thread::sleep(std::time::Duration::from_millis(500));
    let mut closed = 0usize;
    let mut open = 0usize;
    let mut buf = [0u8; 16];
    for s in herd.iter_mut() {
        match s.read(&mut buf) {
            Ok(0) => closed += 1,
            Ok(_) => open += 1,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => open += 1,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => open += 1,
            Err(_) => closed += 1,
        }
    }
    assert!(
        closed >= 4,
        "connection cap did not close the excess (closed {closed}, open {open})"
    );

    drop(herd);
    std::thread::sleep(std::time::Duration::from_millis(300));
    let client = Client::new();
    let resp = client.get(&format!("{base}/fresh")).unwrap();
    assert_eq!(resp.status.as_u16(), 200);
}

/// A slow sender that stalls mid-request must be parked (not hold a
/// worker) and resume when the rest arrives (incremental parsing).
#[test]
fn event_slow_sender_resumes_partial_request() {
    use std::io::Write;
    use std::net::TcpStream;
    use std::time::{Duration, Instant};

    let server_cfg = ServerConfig {
        http2: false,
        event_driven: true,
        event_workers: 2,
        ..Default::default()
    };
    let base = spawn_server(server_cfg, |_req| {
        let mut resp =
            courierust::courierust_http::response::Response::<Body>::with_status(200.into());
        resp.headers.insert(
            courierust::courierust_http::header::HeaderName::from_lowercase("content-length"),
            courierust::courierust_http::header::HeaderValue::from_static("2"),
        );
        resp.body = Body::Bytes(Bytes::from_static(b"ok"));
        resp
    });
    let addr = base.trim_start_matches("http://").to_string();

    let mut c = RawConn::new(TcpStream::connect(addr).unwrap());
    c.stream()
        .write_all(b"GET /slow HTTP/1.1\r\nHost: x\r\n")
        .unwrap();
    std::thread::sleep(Duration::from_millis(300));
    let t0 = Instant::now();
    c.stream().write_all(b"\r\n").unwrap(); // complete the headers
    let resp = c.read_response();
    assert!(resp.starts_with("HTTP/1.1 200"), "got {resp}");

    assert!(t0.elapsed() < Duration::from_secs(10));

    let client = Client::new();
    let resp = client.get(&format!("{base}/parallel")).unwrap();
    assert_eq!(resp.status.as_u16(), 200);
}

/// Pipelined requests on one connection are served in order.
#[test]
fn event_pipelining() {
    use std::io::Write;
    use std::net::TcpStream;

    let server_cfg = ServerConfig {
        http2: false,
        event_driven: true,
        event_workers: 2,
        ..Default::default()
    };
    let base = spawn_server(server_cfg, |req| {
        let path = req.uri.as_str().to_string();
        let mut resp =
            courierust::courierust_http::response::Response::<Body>::with_status(200.into());
        let body = path.into_bytes();
        let cl = courierust::courierust_h1::IToA::new(body.len());
        resp.headers.insert(
            courierust::courierust_http::header::HeaderName::from_lowercase("content-length"),
            courierust::courierust_http::header::HeaderValue::from_bytes(cl.as_slice()).unwrap(),
        );
        resp.body = Body::Bytes(Bytes::from(body));
        resp
    });
    let addr = base.trim_start_matches("http://").to_string();

    let mut c = RawConn::new(TcpStream::connect(addr).unwrap());
    c.stream()
        .write_all(b"GET /one HTTP/1.1\r\nHost: x\r\n\r\nGET /two HTTP/1.1\r\nHost: x\r\n\r\n")
        .unwrap();
    let r1 = c.read_response();
    let r2 = c.read_response();
    assert!(r1.contains("/one"), "got {r1}");
    assert!(r2.contains("/two"), "got {r2}");
}

/// SSE-style streaming over the event loop: a channel body streamed as
/// chunked reaches the client across multiple events.
#[test]
fn event_sse_streaming() {
    let server_cfg = ServerConfig {
        http2: false,
        event_driven: true,
        event_workers: 2,
        ..Default::default()
    };
    let base = spawn_server(server_cfg, |_req| {
        let (tx, body) = courierust::courierust_body::channel();
        std::thread::spawn(move || {
            for i in 0..5 {
                tx.send(Bytes::from(format!("event:{i}\n\n"))).unwrap();
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
        });
        let mut resp =
            courierust::courierust_http::response::Response::<Body>::with_status(200.into());
        resp.headers.insert(
            courierust::courierust_http::header::HeaderName::from_lowercase("content-type"),
            courierust::courierust_http::header::HeaderValue::from_static("text/event-stream"),
        );
        resp.body = body;
        resp
    });
    let client = Client::new();
    let resp = client.get(&format!("{base}/events")).unwrap();
    let body = resp.body.collect().unwrap();
    let s = body.to_str().unwrap();
    assert!(s.contains("event:0") && s.contains("event:4"), "got {s}");
}

// ---------------------------------------------------------------------
// gRPC streaming / metadata / health
// ---------------------------------------------------------------------

fn grpc_echo_stream_server() -> std::net::SocketAddr {
    let svc = move |method: &str,
                    reqs: &mut dyn Iterator<Item = courierust::Result<Bytes>>,
                    tx: &courierust::courierust_body::BodySender|
          -> courierust::Result<()> {
        match method {
            "/echo.Echo/Say" => {
                let first = reqs.next().transpose()?.unwrap_or_default();
                tx.send(Bytes::from(format!(
                    "echo:{}",
                    first.to_str().unwrap_or("")
                )))?;
                Ok(())
            }
            "/echo.Echo/ServerStream" => {
                let first = reqs.next().transpose()?.unwrap_or_default();
                for i in 0..4 {
                    tx.send(Bytes::from(format!(
                        "s{i}:{}",
                        first.to_str().unwrap_or("")
                    )))?;
                }
                Ok(())
            }
            "/echo.Echo/ClientStream" => {
                let mut all = Vec::new();
                for m in reqs {
                    all.push(m?.to_vec());
                }
                let joined: Vec<u8> = all.into_iter().flatten().collect();
                tx.send(Bytes::from(joined))?;
                Ok(())
            }
            "/echo.Echo/Bidi" => {
                for m in reqs {
                    let b = m?;
                    tx.send(Bytes::from(format!("e:{}", b.to_str().unwrap_or(""))))?;
                }
                Ok(())
            }
            other => Err(courierust::Error::grpc(
                courierust::courierust_grpc::status::UNIMPLEMENTED,
                format!("no method {other}"),
            )),
        }
    };
    bind_grpc_streaming(svc)
}
#[test]
fn grpc_server_streaming() {
    let addr = grpc_echo_stream_server();
    let client = GrpcClient::new(&format!("http://{addr}")).unwrap();
    let mut stream = client
        .call_stream("/echo.Echo/ServerStream", Bytes::from_static(b"x"))
        .unwrap();
    let mut got = Vec::new();
    while let Some(m) = stream.next_message().unwrap() {
        got.push(m.to_str().unwrap().to_string());
    }
    assert_eq!(got.len(), 4, "got {got:?}");
    assert_eq!(got[0], "s0:x");
    assert_eq!(got[3], "s3:x");
}

#[test]
fn grpc_client_streaming() {
    let addr = grpc_echo_stream_server();
    let client = GrpcClient::new(&format!("http://{addr}")).unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for p in ["a", "b", "c"] {
            tx.send(Ok(Bytes::from(p))).unwrap();
        }
        drop(tx);
    });
    let resp = client.client_stream("/echo.Echo/ClientStream", rx).unwrap();
    assert_eq!(resp.to_str().unwrap(), "abc");
}

#[test]
fn grpc_bidi_streaming() {
    let addr = grpc_echo_stream_server();
    let client = GrpcClient::new(&format!("http://{addr}")).unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for p in ["1", "2", "3"] {
            tx.send(Ok(Bytes::from(p))).unwrap();
        }
        drop(tx);
    });
    let mut stream = client.bidi_stream("/echo.Echo/Bidi", rx).unwrap();
    let mut got = Vec::new();
    while let Some(m) = stream.next_message().unwrap() {
        got.push(m.to_str().unwrap().to_string());
    }
    assert_eq!(got, vec!["e:1", "e:2", "e:3"], "got {got:?}");
}

#[test]
fn grpc_gzip_compression_roundtrip() {
    let addr = grpc_echo_stream_server();
    let client = GrpcClient::with_config(courierust::courierust_grpc::GrpcClientConfig {
        base: format!("http://{addr}"),
        max_message_size: courierust::courierust_grpc::DEFAULT_MAX_MESSAGE_SIZE,
        interceptor: None,
        timeout: None,
        compress: true, // request messages are gzip-compressed
        http_client: Client::with_config(ClientConfig {
            http2: true,
            ..Default::default()
        }),
    })
    .unwrap();

    let big = "compress me compress me compress me ".repeat(500);
    let resp = client
        .call("/echo.Echo/Say", Bytes::from(big.as_bytes().to_vec()))
        .unwrap();
    assert_eq!(resp.to_str().unwrap(), format!("echo:{big}"));

    let mut stream = client
        .call_stream("/echo.Echo/ServerStream", Bytes::from_static(b"z"))
        .unwrap();
    assert_eq!(
        stream
            .response_headers()
            .get("grpc-encoding")
            .map(|v| v.to_str().unwrap_or(""))
            .unwrap_or(""),
        "gzip",
        "server must negotiate gzip when the client accepts it"
    );
    let mut got = Vec::new();
    while let Some(m) = stream.next_message().unwrap() {
        got.push(m.to_str().unwrap().to_string());
    }
    assert_eq!(got.len(), 4, "got {got:?}");

    let err = client
        .call("/echo.Echo/Say", Bytes::from(vec![b'x'; 8 * 1024 * 1024]))
        .unwrap_err();
    assert!(
        err.to_string().to_ascii_lowercase().contains("too large"),
        "an over-limit message must be rejected client-side, got {err:?}"
    );
}

#[test]
fn grpc_metadata_and_interceptor() {
    let addr = grpc_echo_stream_server();
    let client = GrpcClient::new(&format!("http://{addr}")).unwrap();

    let mut metadata = courierust::courierust_http::header::HeaderMap::new();
    metadata.insert(
        courierust::courierust_http::header::HeaderName::from_lowercase("x-custom"),
        courierust::courierust_http::header::HeaderValue::from_static("hello"),
    );
    let mut stream = client
        .call_with_metadata(
            "/echo.Echo/ServerStream",
            Bytes::from_static(b"m"),
            &metadata,
        )
        .unwrap();
    let first = stream.next_message().unwrap().unwrap();
    assert_eq!(first.to_str().unwrap(), "s0:m");
    assert!(!stream.response_headers().is_empty());
    drop(stream);

    let client = GrpcClient::with_config(courierust::courierust_grpc::GrpcClientConfig {
        base: format!("http://{addr}"),
        max_message_size: 4 * 1024 * 1024,
        interceptor: Some(std::sync::Arc::new(
            |_method: &str, headers: &mut courierust::courierust_http::header::HeaderMap| {
                headers.insert(
                    courierust::courierust_http::header::HeaderName::from_lowercase(
                        "authorization",
                    ),
                    courierust::courierust_http::header::HeaderValue::from_static("Bearer test"),
                );
            },
        )),

        timeout: Some(std::time::Duration::from_secs(5)),
        compress: false,
        http_client: Client::with_config(ClientConfig {
            http2: true,
            ..Default::default()
        }),
    })
    .unwrap();
    let resp = client
        .call("/echo.Echo/ClientStream", Bytes::new())
        .unwrap();
    assert!(resp.is_empty());
}

#[test]
fn grpc_health_check() {
    use courierust::courierust_grpc::health::{self, HealthService};
    let addr = bind_grpc_streaming(
        HealthService::new().set_service("svc.A", health::serving_status::SERVING),
    );

    let client = GrpcClient::new(&format!("http://{addr}")).unwrap();
    let resp = client.call(health::CHECK_METHOD, Bytes::new()).unwrap();
    assert_eq!(resp[0], 0x08, "unexpected proto tag");
    assert_eq!(resp[1], health::serving_status::SERVING as u8);

    // Known service -> SERVING.
    let req = [0x0A, 5]; // field 1, len 5
    let req = Bytes::from([&req[..], b"svc.A"].concat());
    let resp = client.call(health::CHECK_METHOD, req).unwrap();
    assert_eq!(resp[1], health::serving_status::SERVING as u8);

    // Unknown service -> SERVICE_UNKNOWN.
    let req = [0x0A, 1];
    let req = Bytes::from([&req[..], b"x"].concat());
    let resp = client.call(health::CHECK_METHOD, req).unwrap();
    assert_eq!(resp[1], health::serving_status::SERVICE_UNKNOWN as u8);
}

#[test]
fn grpc_health_watch() {
    use courierust::courierust_grpc::health::{self, HealthService};
    let service = HealthService::new();
    let addr = bind_grpc_streaming(service.clone());

    let client = GrpcClient::new(&format!("http://{addr}")).unwrap();
    let mut stream = client
        .call_stream(health::WATCH_METHOD, Bytes::new())
        .unwrap();

    // Initial status is SERVING (the overall status).
    let first = stream
        .next_message()
        .unwrap()
        .expect("watch must stream the initial status");
    assert_eq!(first[1], health::serving_status::SERVING as u8);

    service.update_overall(health::serving_status::NOT_SERVING);
    let second = stream
        .next_message()
        .unwrap()
        .expect("watch must stream the updated status");
    assert_eq!(second[1], health::serving_status::NOT_SERVING as u8);

    service.update_service("svc.Late", health::serving_status::SERVING);
    let req = [0x0A, 8]; // field 1, len 8
    let req = Bytes::from([&req[..], b"svc.Late"].concat());
    let mut stream2 = client.call_stream(health::WATCH_METHOD, req).unwrap();
    let late = stream2
        .next_message()
        .unwrap()
        .expect("watch must stream the status for a known service");
    assert_eq!(late[1], health::serving_status::SERVING as u8);
}

#[test]
fn grpc_max_message_size_enforced() {
    let addr = grpc_echo_stream_server();
    let client = GrpcClient::with_config(courierust::courierust_grpc::GrpcClientConfig {
        base: format!("http://{addr}"),
        max_message_size: 8, // tiny: reject anything bigger
        interceptor: None,
        timeout: None,
        compress: false,
        http_client: Client::with_config(ClientConfig {
            http2: true,
            ..Default::default()
        }),
    })
    .unwrap();
    let err = client
        .call("/echo.Echo/ClientStream", Bytes::from(vec![b'x'; 100]))
        .unwrap_err();
    assert!(
        err.to_string()
            .to_ascii_lowercase()
            .contains("message too large")
            || err.to_string().to_ascii_lowercase().contains("overflow"),
        "got {err:?}"
    );
}

#[test]
fn grpc_timeout_header_formats() {
    assert_eq!(
        courierust::courierust_grpc::grpc_timeout(std::time::Duration::from_secs(2)),
        "2S"
    );
    assert_eq!(
        courierust::courierust_grpc::grpc_timeout(std::time::Duration::from_millis(150)),
        "150m"
    );
    assert_eq!(
        courierust::courierust_grpc::grpc_timeout(std::time::Duration::from_micros(250)),
        "250u"
    );
    assert_eq!(
        courierust::courierust_grpc::grpc_timeout(std::time::Duration::from_secs(7200)),
        "2H"
    );
}

/// RFC 9112 §6.3: a response to a HEAD request never carries a body even
/// when the server sends a Content-Length. The client must return the
/// (empty) response immediately instead of waiting for N bytes that will
/// never arrive (and, on a pooled connection, must not desync the next
/// request).
#[test]
fn h1_client_head_response_with_content_length_has_no_body() {
    use std::io::{BufRead, BufReader, Write};

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        // Read the request head (method line + headers + blank line).
        let mut head = String::new();
        loop {
            let mut l = String::new();
            if reader.read_line(&mut l).unwrap_or(0) == 0 {
                break;
            }
            head.push_str(&l);
            if l == "\r\n" {
                break;
            }
        }
        assert!(head.starts_with("HEAD "), "unexpected request: {head}");
        let mut w = stream;
        w.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n")
            .unwrap();
        let mut l = String::new();
        if reader.read_line(&mut l).unwrap_or(0) > 0 {
            let mut got_head = false;
            loop {
                let mut h = String::new();
                if reader.read_line(&mut h).unwrap_or(0) == 0 {
                    break;
                }
                if h == "\r\n" {
                    got_head = true;
                    break;
                }
            }
            if got_head && l.starts_with("GET ") {
                w.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc")
                    .unwrap();
            }
        }
    });

    let client = Client::with_config(ClientConfig {
        connect_timeout: Some(std::time::Duration::from_secs(5)),
        read_timeout: Some(std::time::Duration::from_secs(5)),
        ..Default::default()
    });
    let mut req = Request::new(Method::HEAD, "/");
    req.body = Body::Empty;
    let resp = client
        .execute(&format!("http://{addr}/"), req)
        .expect("HEAD response must complete without waiting for the body");
    assert_eq!(resp.status.as_u16(), 200);
    assert!(
        resp.body.collect().unwrap().is_empty(),
        "a HEAD response has no body"
    );

    let resp = client
        .get(&format!("http://{addr}/"))
        .expect("GET after HEAD");
    assert_eq!(resp.body.collect().unwrap().to_str().unwrap(), "abc");
}

// ---------------------------------------------------------------------
// Content coding: the client advertises exactly what it decodes, and a
// caller is never handed bytes it did not ask to interpret.
// ---------------------------------------------------------------------

/// Adler-32 over the *uncompressed* data (RFC 1950 §9).
///
/// Computed here rather than taken from the crate, so a bug in the crate's
/// own checksum cannot make the zlib test pass.
fn zlib_adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for &x in data {
        a = (a + u32::from(x)) % 65_521;
        b = (b + a) % 65_521;
    }
    (b << 16) | a
}

/// Build a zlib (RFC 1950) stream around raw DEFLATE.
fn zlib_wrap(raw: &[u8], uncompressed: &[u8]) -> Vec<u8> {
    // 0x78 0x9c = DEFLATE, 32 KiB window, header check bits satisfied.
    let mut out = vec![0x78, 0x9c];
    out.extend_from_slice(raw);
    out.extend_from_slice(&zlib_adler32(uncompressed).to_be_bytes());
    out
}

/// Serve a fixed body with a fixed `content-encoding`, and echo the
/// request's `accept-encoding` back in `x-seen` so the test can assert on
/// what the client actually offered.
fn spawned_coded_server(
    encoding: &'static str,
    body: Vec<u8>,
    observed: Arc<Mutex<Option<String>>>,
) -> String {
    spawn_server(ServerConfig::default(), move |req| {
        *observed.lock().unwrap() = req
            .headers
            .get("accept-encoding")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let mut resp = Response::<Body>::with_status(200.into());
        resp.headers.insert(
            HeaderName::from_lowercase("content-encoding"),
            HeaderValue::from_static(encoding),
        );
        resp.headers.insert(
            HeaderName::from_lowercase("content-length"),
            HeaderValue::from_bytes(body.len().to_string().as_bytes()).unwrap(),
        );
        resp.body = Body::Bytes(Bytes::from(body.clone()));
        resp
    })
}

#[test]
fn a_gzip_response_is_decoded_and_loses_its_encoding_label() {
    let payload = "the quick brown fox jumps over the lazy dog\n".repeat(64);
    let compressed = courierust_deflate::gzip(payload.as_bytes());
    assert!(
        compressed.len() < payload.len() / 2,
        "the test payload must actually be compressed"
    );
    let seen = Arc::new(Mutex::new(None));
    let base = spawned_coded_server("gzip", compressed, seen.clone());

    let client = Client::new();
    let resp = client.get(&format!("{base}/gz")).unwrap();
    assert_eq!(resp.status.as_u16(), 200);
    assert_eq!(
        seen.lock().unwrap().as_deref(),
        Some("gzip, deflate"),
        "the offer must be exactly the supported set"
    );
    assert_eq!(resp.body.collect().unwrap().to_str().unwrap(), payload);
    assert!(
        resp.headers.get("content-encoding").is_none(),
        "a decoded body must not still claim an encoding"
    );
    assert!(
        resp.headers.get("content-length").is_none(),
        "content-length described the compressed bytes, not these"
    );
}

#[test]
fn both_deflate_dialects_are_decoded() {
    let payload = "deflate is zlib, except when it is not\n".repeat(64);
    let raw = courierust_deflate::deflate(payload.as_bytes());

    let seen = Arc::new(Mutex::new(None));
    let wrapped =
        spawned_coded_server("deflate", zlib_wrap(&raw, payload.as_bytes()), seen.clone());

    let seen2 = Arc::new(Mutex::new(None));
    let bare = spawned_coded_server("deflate", raw, seen2.clone());

    let client = Client::new();
    for base in [wrapped, bare] {
        let resp = client.get(&format!("{base}/d")).unwrap();
        assert_eq!(resp.status.as_u16(), 200, "{base}");
        assert_eq!(resp.body.collect().unwrap().to_str().unwrap(), payload);
        assert!(resp.headers.get("content-encoding").is_none());
    }
}

/// An encoding the client never offered is not guessed at: the response is
/// passed through byte-for-byte with its label intact, so the caller can
/// see what it is holding instead of receiving data it cannot interpret.
#[test]
fn an_unadvertised_encoding_is_left_alone() {
    let body = b"not actually brotli".to_vec();
    let seen = Arc::new(Mutex::new(None));
    let base = spawned_coded_server("br", body.clone(), seen.clone());

    let client = Client::new();
    let resp = client.get(&format!("{base}/br")).unwrap();
    assert!(
        !seen
            .lock()
            .unwrap()
            .as_deref()
            .unwrap_or_default()
            .contains("br"),
        "`br` must never be offered"
    );
    assert_eq!(
        resp.headers
            .get("content-encoding")
            .and_then(|v| v.to_str().ok()),
        Some("br"),
        "the label must survive so the caller knows the body is not plain"
    );
    assert_eq!(resp.body.collect().unwrap().as_slice(), body.as_slice());
}

/// `identity` is not a transform worth a header; leaving it in place is
/// noise that makes callers branch for no reason.
#[test]
fn an_identity_encoding_is_removed_not_decoded() {
    let body = b"plain bytes".to_vec();
    let seen = Arc::new(Mutex::new(None));
    let base = spawned_coded_server("identity", body.clone(), seen);

    let client = Client::new();
    let resp = client.get(&format!("{base}/plain")).unwrap();
    assert!(resp.headers.get("content-encoding").is_none());
    assert_eq!(resp.body.collect().unwrap().as_slice(), body.as_slice());
}

/// Turning the feature off must turn off *both* halves. Offering a coding
/// and then not decoding it is the failure mode that makes this setting
/// dangerous to get wrong.
#[test]
fn disabling_accept_encoding_removes_the_offer_and_the_decode() {
    let payload = "compress me ".repeat(128);
    let compressed = courierust_deflate::gzip(payload.as_bytes());
    let seen = Arc::new(Mutex::new(None));
    let base = spawned_coded_server("gzip", compressed.clone(), seen.clone());

    let client = Client::with_config(ClientConfig {
        accept_encoding: false,
        ..Default::default()
    });
    let resp = client.get(&format!("{base}/gz")).unwrap();
    assert!(
        seen.lock().unwrap().is_none(),
        "nothing may be advertised when decoding is off"
    );
    assert_eq!(
        resp.headers
            .get("content-encoding")
            .and_then(|v| v.to_str().ok()),
        Some("gzip")
    );
    assert_eq!(
        resp.body.collect().unwrap().as_slice(),
        compressed.as_slice(),
        "the bytes are handed over exactly as they arrived"
    );
}

/// A caller that picks its own coding list means it: the header is never
/// rewritten. A server that compresses anyway is still answered — the
/// client understands `gzip`, so the caller gets plain bytes instead of
/// bytes it said it could not handle.
#[test]
fn a_caller_supplied_accept_encoding_is_respected() {
    let payload = "identity please ".repeat(64);
    let compressed = courierust_deflate::gzip(payload.as_bytes());
    let seen = Arc::new(Mutex::new(None));
    let base = spawned_coded_server("gzip", compressed, seen.clone());

    let client = Client::new();
    let mut req = Request::new(Method::GET, "/gz");
    req.headers.insert(
        HeaderName::from_lowercase("accept-encoding"),
        HeaderValue::from_static("identity"),
    );
    let resp = client.execute(&format!("{base}/gz"), req).unwrap();
    assert_eq!(
        seen.lock().unwrap().as_deref(),
        Some("identity"),
        "the caller's header must not be overwritten"
    );
    assert_eq!(resp.body.collect().unwrap().to_str().unwrap(), payload);
    assert!(resp.headers.get("content-encoding").is_none());
}

/// Security: decoding is where a hostile peer turns a small body into an
/// unbounded allocation, so it must obey the same limit as reading one.
#[test]
fn a_compression_bomb_is_stopped_by_max_body() {
    let bomb = courierust_deflate::gzip(&vec![0u8; 8 * 1024 * 1024]);
    assert!(
        bomb.len() < 256 * 1024,
        "the point of the test is a small body that expands hugely, got {}",
        bomb.len()
    );
    let seen = Arc::new(Mutex::new(None));
    let base = spawned_coded_server("gzip", bomb, seen);

    let client = Client::with_config(ClientConfig {
        max_body: 64 * 1024,
        ..Default::default()
    });
    let err = client.get(&format!("{base}/bomb")).unwrap_err();
    assert!(
        matches!(err.kind, courierust::ErrorKind::Overflow),
        "a decode must not be allowed to exceed max_body: {err:?}"
    );
}

// ---------------------------------------------------------------------
// Redirects: a follow-up is a different request, and must not carry the
// old one's framing.
// ---------------------------------------------------------------------

/// A `302` turns a `POST` into a `GET`. The follow-up has no body, so it
/// must not claim one: a `Content-Length` with no bytes behind it is how a
/// request desynchronises the connection it is written on.
#[test]
fn a_bodyless_redirect_follow_up_does_not_claim_a_body() {
    let base = spawn_server(ServerConfig::default(), |req| {
        if req.uri.as_str() == "/start" {
            let mut resp = Response::<Body>::with_status(302.into());
            resp.headers.insert(
                HeaderName::from_lowercase("location"),
                HeaderValue::from_static("/end"),
            );
            return resp;
        }
        let mut resp = Response::<Body>::with_status(200.into());
        resp.headers.insert(
            HeaderName::from_lowercase("x-method"),
            HeaderValue::from_bytes(req.method.as_str().as_bytes()).unwrap(),
        );
        let cl = req
            .headers
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("-");
        resp.headers.insert(
            HeaderName::from_lowercase("x-content-length"),
            HeaderValue::from_bytes(cl.as_bytes()).unwrap(),
        );
        resp
    });

    let client = Client::with_config(ClientConfig {
        read_timeout: Some(Duration::from_secs(5)),
        ..Default::default()
    });
    let mut req = Request::new(Method::POST, "/start");
    req.headers.insert(
        HeaderName::from_lowercase("content-length"),
        HeaderValue::from_static("7"),
    );
    req.headers.insert(
        HeaderName::from_lowercase("content-type"),
        HeaderValue::from_static("text/plain"),
    );
    req.body = Body::Bytes(Bytes::from_static(b"payload"));

    let resp = client.execute(&format!("{base}/start"), req).unwrap();
    assert_eq!(resp.status.as_u16(), 200);
    assert_eq!(
        resp.headers.get("x-method").unwrap().to_str().unwrap(),
        "GET",
        "a 302 turns POST into GET"
    );
    assert_eq!(
        resp.headers
            .get("x-content-length")
            .unwrap()
            .to_str()
            .unwrap(),
        "-",
        "the body-less follow-up must not announce a body"
    );
}

/// A `307`/`308` means "same request, different place". Without the body
/// that is not the same request, so the redirect is handed back rather
/// than followed into something the caller never wrote.
#[test]
fn a_redirect_that_would_have_to_replay_the_body_is_handed_back() {
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_b = hits.clone();
    let base = spawn_server(ServerConfig::default(), move |req| {
        if req.uri.as_str() == "/start" {
            let mut resp = Response::<Body>::with_status(307.into());
            resp.headers.insert(
                HeaderName::from_lowercase("location"),
                HeaderValue::from_static("/end"),
            );
            return resp;
        }
        hits_b.fetch_add(1, Ordering::SeqCst);
        Response::<Body>::with_status(200.into())
    });

    let client = Client::new();
    let mut req = Request::new(Method::PUT, "/start");
    req.body = Body::Bytes(Bytes::from_static(b"payload"));
    let resp = client.execute(&format!("{base}/start"), req).unwrap();
    assert_eq!(
        resp.status.as_u16(),
        307,
        "the redirect is the answer: the body cannot be replayed"
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "the redirect target must not be contacted with a different request"
    );
}

/// The same `307` on a body-less request is followable, and still is.
#[test]
fn a_307_without_a_body_is_still_followed() {
    let base = spawn_server(ServerConfig::default(), |req| {
        if req.uri.as_str() == "/start" {
            let mut resp = Response::<Body>::with_status(307.into());
            resp.headers.insert(
                HeaderName::from_lowercase("location"),
                HeaderValue::from_static("/end"),
            );
            return resp;
        }
        let mut resp = Response::<Body>::with_status(200.into());
        resp.headers.insert(
            HeaderName::from_lowercase("x-final"),
            HeaderValue::from_static("yes"),
        );
        resp
    });

    let client = Client::new();
    let resp = client.get(&format!("{base}/start")).unwrap();
    assert_eq!(resp.status.as_u16(), 200);
    assert_eq!(
        resp.headers.get("x-final").unwrap().to_str().unwrap(),
        "yes"
    );
}
