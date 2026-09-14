//! End-to-end integration tests: real TCP client↔server over loopback,
//! covering HTTP/1.1, HTTP/2 (h2c), HTTPS (TLS 1.2 + 1.3) and gRPC.

mod common;

use courierust::courierust_body::Body;
use courierust::courierust_bytes::Bytes;
use courierust::courierust_client::{Client, ClientConfig, TlsSettings as ClientTls};
use courierust::courierust_grpc::GrpcClient;
use courierust::courierust_http::method::Method;
use courierust::courierust_http::request::Request;
use courierust::courierust_server::{Server, ServerConfig, TlsSettings as ServerTls};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
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

/// The embedder path: the caller binds, accepts, and hands each socket to
/// `serve_connection` — the shape a proxy needs when it has to decide on a
/// connection (peer address, limits, its own accounting) before the engine
/// sees it. The engine's behaviour must not depend on who owns the loop,
/// so this drives a plain HTTP/1.1 request through an accept loop written
/// right here.
#[test]
fn serve_connection_drives_a_caller_owned_accept_loop() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let config = ServerConfig {
        threads: 1,
        ..Default::default()
    };
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { break };
            let config = config.clone();
            std::thread::spawn(move || {
                let _ =
                    courierust::courierust_server::serve_connection(stream, &echo_handler, &config);
            });
        }
    });

    let client = Client::new();
    let resp = client.get(&format!("http://{addr}/embedded")).unwrap();
    assert_eq!(resp.status.as_u16(), 200);
    assert_eq!(
        resp.headers.get("x-method").unwrap().to_str().unwrap(),
        "GET"
    );
}

/// The other half of the same handle: a listener bound by the caller is
/// adopted with `Server::from_listener`, and everything after that —
/// background serving, the reported `local_addr`, the request loop — is
/// the same server `bind_with_config` would have produced.
#[test]
fn server_adopts_a_caller_bound_listener() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = Server::from_listener(
        listener,
        ServerConfig {
            threads: 1,
            ..Default::default()
        },
    )
    .expect("adopt the bound listener");
    assert_eq!(server.local_addr().unwrap(), addr);
    let handle = server.serve_background(echo_handler).unwrap();
    std::mem::forget(handle); // keep serving for the test process

    let client = Client::new();
    let resp = client
        .post(&format!("http://{addr}/adopted"), "hi")
        .unwrap();
    assert_eq!(resp.status.as_u16(), 200);
    assert_eq!(resp.body.collect().unwrap().to_str().unwrap(), "hi");
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
    use std::sync::Mutex;

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

/// The PEM loader against the real OpenSSL fixtures: a server booted from
/// `server_cert.pem` + `server_key.pem` completes a handshake and serves
/// a request. Parsing alone would not prove this — the pair has to
/// *serve*, and it does so to the same client that validates the DER twin
/// against `common::root_store()`.
#[test]
fn https_server_boots_from_openssl_pem_fixtures() {
    let config = ServerConfig {
        threads: 1,
        tls: Some(
            ServerTls::from_pem_file("tests/certs/server_cert.pem", "tests/certs/server_key.pem")
                .expect("the fixture PEM pair must load"),
        ),
        ..Default::default()
    };
    let base = spawn_tls_server(config, echo_handler);
    let client = Client::with_config(https_client_config(false));
    let resp = client.get(&format!("{base}/pem")).unwrap();
    assert_eq!(resp.status.as_u16(), 200);
    assert_eq!(
        resp.headers.get("x-method").unwrap().to_str().unwrap(),
        "GET"
    );
}

/// A PEM chain file with an intermediate loads as a two-certificate
/// chain, and a key from a different certificate is refused when it is
/// loaded — the failure a deployment wants at startup, not once per
/// client. The P-384 key is what OpenSSL writes for `EC PRIVATE KEY`
/// (SEC1), so this is also the fixture that exercises that container.
#[test]
fn pem_identity_loads_a_chain_and_refuses_a_mismatched_key() {
    let leaf = std::fs::read_to_string("tests/certs/p384_leaf_cert.pem").unwrap();
    let intermediate = std::fs::read_to_string("tests/certs/p384_intermediate_cert.pem").unwrap();
    let key = std::fs::read_to_string("tests/certs/p384_leaf_key.pem").unwrap();
    let identity =
        courierust::courierust_tls::Identity::from_pem(&format!("{leaf}{intermediate}"), &key)
            .expect("leaf + intermediate + key");
    assert_eq!(identity.cert_chain().len(), 2);
    assert!(!identity.is_rsa());

    let err = courierust::courierust_tls::Identity::from_pem(
        &std::fs::read_to_string("tests/certs/server_cert.pem").unwrap(),
        &key,
    )
    .expect_err("an Ed25519 certificate with a P-384 key must be refused");
    assert!(err.to_string().contains("does not match"), "{err}");

    // The trust side of the same story: roots come from files too.
    let mut roots = courierust::courierust_tls::RootStore::new();
    assert_eq!(
        roots.add_pem_file("tests/certs/server_cert.pem").unwrap(),
        1
    );
    assert!(roots
        .add_pem_file("tests/certs/does-not-exist.pem")
        .is_err());
}

/// mTLS through the public configuration surface. The server requires a
/// client certificate and the client presents one, so the request is
/// served; the same server refuses a client that offers none. This is the
/// wiring test: `ServerTls::client_auth` on one side, `ClientTls::identity`
/// on the other, with the handshake policy in between.
#[test]
fn https_server_requires_a_client_certificate() {
    let config = ServerConfig {
        threads: 1,
        tls: Some(ServerTls {
            identity: common::server_identity(),
            alpn: vec![b"http/1.1".to_vec()],
            client_auth: Some(courierust::courierust_tls::ClientAuth::required(
                common::root_store(),
            )),
            ..Default::default()
        }),
        ..Default::default()
    };
    let base = spawn_tls_server(config, echo_handler);

    let authenticated = Client::with_config(ClientConfig {
        tls: Some(ClientTls {
            roots: common::root_store(),
            verify: true,
            alpn: vec![b"http/1.1".to_vec()],
            now: common::NOW,
            identity: Some(common::server_identity()),
            ..Default::default()
        }),
        ..Default::default()
    });
    let resp = authenticated.get(&format!("{base}/mtls")).unwrap();
    assert_eq!(resp.status.as_u16(), 200);

    // The anonymous client is refused: `certificate_required` may surface
    // as an error, and must never become a served response.
    let anonymous = Client::with_config(https_client_config(false));
    if let Ok(resp) = anonymous.get(&format!("{base}/mtls")) {
        assert_ne!(
            resp.status.as_u16(),
            200,
            "a client without a certificate must not be served"
        );
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
    let expired_identity = courierust::courierust_tls::Identity::from_der(
        vec![include_bytes!("certs/expired_cert.der").to_vec()],
        include_bytes!("certs/expired_key.der").to_vec(),
    )
    .expect("valid test identity");
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
    let wrong_chain_identity = courierust::courierust_tls::Identity::from_der(
        vec![
            include_bytes!("certs/wrong_chain_cert.der").to_vec(),
            include_bytes!("certs/ca_other_cert.der").to_vec(),
        ],
        include_bytes!("certs/wrong_chain_key.der").to_vec(),
    )
    .expect("valid test identity");
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

    // Open 8 connections that never complete a request (parked). The
    // first `max_connections` are admitted; the rest are closed by the
    // cap.
    let mut herd = Vec::new();
    for _ in 0..8 {
        let mut s = TcpStream::connect(&addr).unwrap();
        s.set_read_timeout(Some(std::time::Duration::from_millis(400)))
            .unwrap();
        s.write_all(b"GET /partial HTTP/1.1\r\nHost: x\r\n")
            .unwrap();
        herd.push(s);
    }

    // Wait for the event loop to apply the cap, then count how many of
    // the herd were closed by it. The admitted (parked) connections stay
    // open, so exactly the excess should read EOF/error.
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

    // Close the admitted herd, then a fresh request must be served — the
    // cap only rejects while it is full.
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
    // Send a partial request, then stall well beyond any poll timeout.
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

/// A streaming response body must not hold a worker while its producer is
/// between chunks: with a single event worker, a request arriving in the
/// middle of a slow stream is still served immediately. Before the body
/// carried a wake handle the worker blocked on the channel, so that
/// request waited for the whole stream.
#[test]
fn event_streaming_body_does_not_hold_a_worker() {
    use std::io::{Read as _, Write};
    use std::net::TcpStream;
    use std::time::{Duration, Instant};

    let server_cfg = ServerConfig {
        http2: false,
        event_driven: true,
        event_workers: 1,
        ..Default::default()
    };
    let base = spawn_server(server_cfg, |req| {
        if req.uri.as_str() == "/stream" {
            let (tx, body) = courierust::courierust_body::channel();
            std::thread::spawn(move || {
                for i in 0..10 {
                    tx.send(Bytes::from(format!("part-{i}\n"))).unwrap();
                    std::thread::sleep(Duration::from_millis(60));
                }
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
    });
    let addr = base.trim_start_matches("http://").to_string();

    // Start the stream by hand and read its head: the producer needs
    // another ~540 ms to finish, and this connection stays open.
    let mut streamed = TcpStream::connect(addr).unwrap();
    streamed
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    streamed
        .write_all(b"GET /stream HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut head = [0u8; 256];
    let n = streamed.read(&mut head).unwrap();
    assert!(n > 0, "the streaming response must start");

    // The only event worker must still be free for this connection.
    let t0 = Instant::now();
    let client = Client::new();
    let resp = client.get(&format!("{base}/fast")).unwrap();
    let waited = t0.elapsed();
    assert_eq!(resp.body.as_bytes(), Some(&b"fast"[..]));
    assert!(
        waited < Duration::from_millis(250),
        "a stream waiting for its producer held the only worker for {waited:?}"
    );

    // The stream itself still completes, terminator included.
    let mut rest = String::new();
    streamed.read_to_string(&mut rest).unwrap();
    assert!(rest.contains("part-9"), "the stream must finish: {rest:?}");
}

/// A raw `Body::Channel` — built from a plain `std::sync::mpsc` pair, so
/// no producer wake exists — still streams: the transport polls it on its
/// own schedule instead of holding a worker until the producer is done.
#[test]
fn event_raw_channel_body_streams_without_a_wake() {
    let server_cfg = ServerConfig {
        http2: false,
        event_driven: true,
        event_workers: 2,
        ..Default::default()
    };
    let base = spawn_server(server_cfg, |_req| {
        let (tx, rx) = std::sync::mpsc::channel::<courierust::Result<Bytes>>();
        std::thread::spawn(move || {
            for i in 0..5 {
                tx.send(Ok(Bytes::from(format!("raw-{i}\n")))).unwrap();
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
        });
        let mut resp =
            courierust::courierust_http::response::Response::<Body>::with_status(200.into());
        resp.body = Body::Channel(rx);
        resp
    });
    let client = Client::new();
    let resp = client.get(&format!("{base}/raw")).unwrap();
    let body = resp.body.collect().unwrap();
    let s = body.to_str().unwrap();
    assert!(s.contains("raw-0") && s.contains("raw-4"), "got {s}");
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

    // Unary with a highly compressible payload: the server must
    // decompress the gzip request, echo it, and (because our client
    // advertised gzip) compress the response; the client must
    // decompress it.
    let big = "compress me compress me compress me ".repeat(500);
    let resp = client
        .call("/echo.Echo/Say", Bytes::from(big.as_bytes().to_vec()))
        .unwrap();
    assert_eq!(resp.to_str().unwrap(), format!("echo:{big}"));

    // Server-streaming with compression, and verify the negotiated
    // `grpc-encoding` is reported as gzip on the response head.
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

    // An over-limit message is rejected at the client before it is sent
    // (outbound size enforcement — this is what also defeats
    // compression-smuggling, since the uncompressed size is checked).
    // The server-side decompression bomb cap is covered by the
    // `compress` module's `gunzip_enforces_output_cap` unit test.
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
        // Generous: the full suite runs many servers in parallel, so a
        // tight deadline would spuriously trip DEADLINE_EXCEEDED under
        // load. Deadline *enforcement* is tested separately.
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
    // Watch is a server-streaming call: the stream stays open and pushes
    // status changes.
    let mut stream = client
        .call_stream(health::WATCH_METHOD, Bytes::new())
        .unwrap();

    // Initial status is SERVING (the overall status).
    let first = stream
        .next_message()
        .unwrap()
        .expect("watch must stream the initial status");
    assert_eq!(first[1], health::serving_status::SERVING as u8);

    // A runtime status change must be pushed to the open stream.
    service.update_overall(health::serving_status::NOT_SERVING);
    let second = stream
        .next_message()
        .unwrap()
        .expect("watch must stream the updated status");
    assert_eq!(second[1], health::serving_status::NOT_SERVING as u8);

    // A service appearing after the watch started is also pushed.
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
        // A standard HEAD response: 200 with Content-Length but no body.
        let mut w = stream;
        w.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n")
            .unwrap();
        // A subsequent GET on the same keep-alive connection must not be
        // poisoned by the "missing" HEAD body: answer it normally.
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
    // Reuse the same pooled connection for a GET; if the HEAD body were
    // mis-framed the connection would desync and this would fail/hang.
    let resp = client
        .get(&format!("http://{addr}/"))
        .expect("GET after HEAD");
    assert_eq!(resp.body.collect().unwrap().to_str().unwrap(), "abc");
}

// ---------------------------------------------------------------------
// Client keep-alive pool: a pooled connection can die while it is idle
// (the server's own keep-alive timeout, a proxy, a restart). The pool
// probes before reusing, and a connection that turns out to be spent is
// re-opened once for a request that is safe to repeat — never for one
// that is not (RFC 9110 §9.2.2).
// ---------------------------------------------------------------------

/// A stub HTTP/1.1 server that answers the first request with keep-alive
/// and then lets the connection die:
///
/// * `rude`: it stays open until the *second* request arrives, then hangs
///   up without answering — the race a liveness probe cannot see, so only
///   a retry recovers it.
/// * polite: it closes shortly after answering, so the next request finds
///   a spent (but still pooled) connection and the probe must drop it.
///
/// The accept counter tells a test whether the client re-opened.
fn spawn_dying_keep_alive_stub(rude: bool) -> (String, Arc<std::sync::atomic::AtomicUsize>) {
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::sync::atomic::Ordering;

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let accepts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = accepts.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let is_first = counter.fetch_add(1, Ordering::SeqCst) == 0;
            std::thread::spawn(move || {
                let Ok(read_half) = stream.try_clone() else {
                    return;
                };
                let mut reader = BufReader::new(read_half);
                let read_head = |reader: &mut BufReader<std::net::TcpStream>| -> bool {
                    let mut line = String::new();
                    if !matches!(reader.read_line(&mut line), Ok(n) if n > 0) {
                        return false;
                    }
                    loop {
                        let mut rest = String::new();
                        match reader.read_line(&mut rest) {
                            Ok(0) | Err(_) => return false,
                            Ok(_) if rest.trim_end().is_empty() => return true,
                            Ok(_) => {}
                        }
                    }
                };
                if !read_head(&mut reader) {
                    return;
                }
                let (label, close) = if is_first {
                    ("first", false)
                } else {
                    ("second", true)
                };
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n{}\r\n",
                    label.len(),
                    if close { "connection: close\r\n" } else { "" }
                );
                let _ = stream.write_all(label.as_bytes());
                let _ = stream.flush();
                if is_first && rude {
                    // Wait for the next request, then vanish without
                    // answering it.
                    let mut next = String::new();
                    let _ = reader.read_line(&mut next);
                } else if is_first {
                    // Let the client pool the connection, then close it.
                    std::thread::sleep(std::time::Duration::from_millis(40));
                }
                drop(stream);
            });
        }
    });
    (format!("http://{addr}"), accepts)
}

/// RFC 9110 §9.2.2: a GET may be replayed, so a pooled connection that
/// died between requests must not fail the request — the client re-opens
/// once and retries.
#[test]
fn h1_client_retries_idempotent_request_on_a_stale_keep_alive() {
    use std::sync::atomic::Ordering;

    let (base, accepts) = spawn_dying_keep_alive_stub(true);
    let client = Client::new();
    let first = client.get(&format!("{base}/one")).unwrap();
    assert_eq!(first.body.as_bytes(), Some(&b"first"[..]));

    let second = client
        .get(&format!("{base}/two"))
        .expect("a GET must survive a stale pooled connection");
    assert_eq!(second.body.as_bytes(), Some(&b"second"[..]));
    assert_eq!(
        accepts.load(Ordering::SeqCst),
        2,
        "the retry must open exactly one replacement connection"
    );
}

/// The retry must never replay a request whose second execution would be
/// observable: a POST that fails on a spent pooled connection reports the
/// failure instead of being sent again.
#[test]
fn h1_client_never_replays_a_non_idempotent_request() {
    use std::sync::atomic::Ordering;

    let (base, accepts) = spawn_dying_keep_alive_stub(true);
    let client = Client::new();
    let first = client.get(&format!("{base}/one")).unwrap();
    assert_eq!(first.body.as_bytes(), Some(&b"first"[..]));

    let error = client
        .post(
            &format!("{base}/two"),
            Body::Bytes(Bytes::from_static(b"body")),
        )
        .expect_err("a POST must not be replayed");
    assert!(
        matches!(
            error.kind,
            courierust::courierust_error::ErrorKind::UnexpectedEof
                | courierust::courierust_error::ErrorKind::Canceled
        ),
        "got {error:?}"
    );
    assert_eq!(
        accepts.load(Ordering::SeqCst),
        1,
        "no replacement connection may be opened for a POST"
    );
}

/// A connection the peer closed while it sat idle is dropped *before* the
/// next request is written, so even a request that may never be replayed
/// (POST) succeeds — nothing was sent on the dead connection at all.
#[test]
fn h1_client_probes_a_pooled_connection_before_reusing_it() {
    use std::sync::atomic::Ordering;

    let (base, accepts) = spawn_dying_keep_alive_stub(false);
    let client = Client::new();
    let first = client.get(&format!("{base}/one")).unwrap();
    assert_eq!(first.body.as_bytes(), Some(&b"first"[..]));
    // Give the stub's FIN time to arrive: the pooled connection is now
    // spent, and nothing but the probe can know that.
    std::thread::sleep(std::time::Duration::from_millis(100));

    let second = client
        .post(
            &format!("{base}/two"),
            Body::Bytes(Bytes::from_static(b"body")),
        )
        .expect("a POST must be sent on a fresh connection, not a spent one");
    assert_eq!(second.body.as_bytes(), Some(&b"second"[..]));
    assert_eq!(accepts.load(Ordering::SeqCst), 2);
}

// ---------------------------------------------------------------------
// Request building: Client::request, the verb shorthands, per-request
// deadlines and client default headers.
// ---------------------------------------------------------------------

/// Report back what the server saw: method, request target, a few headers
/// and the body.
fn meta_handler(
    req: courierust::courierust_http::request::Request<Body>,
) -> courierust::courierust_http::response::Response<Body> {
    use courierust::courierust_http::header::{HeaderName, HeaderValue};
    let mut resp = courierust::courierust_http::response::Response::<Body>::with_status(200.into());
    resp.headers.insert(
        HeaderName::from_lowercase("x-method"),
        HeaderValue::from_bytes(req.method.as_str().as_bytes()).unwrap(),
    );
    resp.headers.insert(
        HeaderName::from_lowercase("x-target"),
        HeaderValue::from_bytes(req.uri.as_str().as_bytes()).unwrap(),
    );
    for name in [
        "authorization",
        "cookie",
        "content-type",
        "accept",
        "x-client",
    ] {
        if let Some(value) = req.headers.get(name) {
            resp.headers.insert(
                HeaderName::from_bytes(format!("x-seen-{name}").as_bytes()).unwrap(),
                value.clone(),
            );
        }
    }
    resp.body = Body::Bytes(req.body.collect().unwrap());
    resp
}

#[test]
fn builder_and_verb_shorthands_send_every_method() {
    let base = spawn_server(ServerConfig::default(), meta_handler);
    let client = Client::new();

    for (method, expected) in [
        (Method::GET, "GET"),
        (Method::PUT, "PUT"),
        (Method::PATCH, "PATCH"),
        (Method::DELETE, "DELETE"),
        (Method::HEAD, "HEAD"),
        (Method::OPTIONS, "OPTIONS"),
    ] {
        // RFC 9110 gives a content to PUT and PATCH (and POST); a HEAD
        // or GET carrying one would be a different test.
        let builder = client.request(&format!("{base}/thing"), method.clone());
        let builder = if matches!(method, Method::PUT | Method::PATCH) {
            builder.body("payload")
        } else {
            builder
        };
        let resp = builder
            .send()
            .unwrap_or_else(|e| panic!("{method:?} failed: {e}"));
        assert_eq!(resp.status.as_u16(), 200);
        assert_eq!(
            resp.headers.get("x-method").unwrap().to_str().unwrap(),
            expected
        );
    }

    // The shorthands cover the same verbs without a builder chain.
    assert_eq!(
        client
            .put(&format!("{base}/a"), "p")
            .unwrap()
            .headers
            .get("x-method")
            .unwrap()
            .to_str()
            .unwrap(),
        "PUT"
    );
    assert_eq!(
        client
            .delete(&format!("{base}/a"))
            .unwrap()
            .headers
            .get("x-method")
            .unwrap()
            .to_str()
            .unwrap(),
        "DELETE"
    );
    assert_eq!(
        client
            .patch(&format!("{base}/a"), "p")
            .unwrap()
            .headers
            .get("x-method")
            .unwrap()
            .to_str()
            .unwrap(),
        "PATCH"
    );
    assert_eq!(
        client
            .head(&format!("{base}/a"))
            .unwrap()
            .headers
            .get("x-method")
            .unwrap()
            .to_str()
            .unwrap(),
        "HEAD"
    );
    assert_eq!(
        client
            .options(&format!("{base}/a"))
            .unwrap()
            .headers
            .get("x-method")
            .unwrap()
            .to_str()
            .unwrap(),
        "OPTIONS"
    );
}

#[test]
fn builder_encodes_query_and_form_fields() {
    let base = spawn_server(ServerConfig::default(), meta_handler);
    let client = Client::new();

    let resp = client
        .request(&format!("{base}/search"), Method::GET)
        .query([("q", "a b&c"), ("page", "2")])
        .send()
        .unwrap();
    assert_eq!(
        resp.headers.get("x-target").unwrap().to_str().unwrap(),
        "/search?q=a+b%26c&page=2"
    );

    let resp = client
        .request(&format!("{base}/submit"), Method::POST)
        .form([("name", "中文 值"), ("flag", "1")])
        .send()
        .unwrap();
    assert_eq!(
        resp.headers
            .get("x-seen-content-type")
            .unwrap()
            .to_str()
            .unwrap(),
        "application/x-www-form-urlencoded"
    );
    assert_eq!(
        resp.text().unwrap(),
        "name=%E4%B8%AD%E6%96%87+%E5%80%BC&flag=1"
    );
}

#[test]
fn builder_auth_headers_are_the_expected_field_values() {
    let base = spawn_server(ServerConfig::default(), meta_handler);
    let client = Client::new();

    let resp = client
        .request(&format!("{base}/a"), Method::GET)
        .basic_auth("user", "secret")
        .send()
        .unwrap();
    assert_eq!(
        resp.headers
            .get("x-seen-authorization")
            .unwrap()
            .to_str()
            .unwrap(),
        "Basic dXNlcjpzZWNyZXQ="
    );

    let resp = client
        .request(&format!("{base}/a"), Method::GET)
        .bearer_auth("tok en")
        .send()
        .unwrap();
    assert_eq!(
        resp.headers
            .get("x-seen-authorization")
            .unwrap()
            .to_str()
            .unwrap(),
        "Bearer tok en"
    );
}

#[test]
fn client_default_headers_apply_but_a_request_field_wins() {
    use courierust::courierust_http::header::{HeaderName, HeaderValue};

    let base = spawn_server(ServerConfig::default(), meta_handler);
    let mut default_headers = courierust::courierust_http::header::HeaderMap::new();
    default_headers.insert(
        HeaderName::from_lowercase("x-client"),
        HeaderValue::from_static("courierust-test"),
    );
    default_headers.insert(
        HeaderName::from_lowercase("accept"),
        HeaderValue::from_static("application/json"),
    );
    let client = Client::with_config(ClientConfig {
        default_headers,
        ..Default::default()
    });

    let resp = client.get(&format!("{base}/a")).unwrap();
    assert_eq!(
        resp.headers
            .get("x-seen-x-client")
            .unwrap()
            .to_str()
            .unwrap(),
        "courierust-test"
    );
    assert_eq!(
        resp.headers.get("x-seen-accept").unwrap().to_str().unwrap(),
        "application/json"
    );

    let resp = client
        .request(&format!("{base}/a"), Method::GET)
        .header("accept", "text/plain")
        .send()
        .unwrap();
    assert_eq!(
        resp.headers.get("x-seen-accept").unwrap().to_str().unwrap(),
        "text/plain",
        "a field on the request itself must not be replaced by a default"
    );
}

/// A default credential is the one most easily forgotten about: it is not
/// visible at the call site that follows a redirect to another origin.
#[test]
fn default_credentials_do_not_cross_origins() {
    use courierust::courierust_http::header::{HeaderMap, HeaderName, HeaderValue};

    let base_b = spawn_server(ServerConfig::default(), meta_handler);
    let location = base_b.to_string();
    let base_a = spawn_server(ServerConfig::default(), move |_req| {
        let mut resp =
            courierust::courierust_http::response::Response::<Body>::with_status(302.into());
        resp.headers.insert(
            HeaderName::from_lowercase("location"),
            HeaderValue::from_bytes(location.as_bytes()).unwrap(),
        );
        resp
    });

    let mut default_headers = HeaderMap::new();
    default_headers.insert(
        HeaderName::from_lowercase("authorization"),
        HeaderValue::from_static("Bearer config-secret"),
    );
    default_headers.insert(
        HeaderName::from_lowercase("cookie"),
        HeaderValue::from_static("session=1"),
    );
    default_headers.insert(
        HeaderName::from_lowercase("x-client"),
        HeaderValue::from_static("courierust-test"),
    );
    let client = Client::with_config(ClientConfig {
        default_headers,
        ..Default::default()
    });

    let resp = client.get(&format!("{base_a}/start")).unwrap();
    assert_eq!(resp.status.as_u16(), 200);
    assert!(resp.headers.get("x-seen-authorization").is_none());
    assert!(resp.headers.get("x-seen-cookie").is_none());
    assert_eq!(
        resp.headers
            .get("x-seen-x-client")
            .unwrap()
            .to_str()
            .unwrap(),
        "courierust-test",
        "a non-credential default still applies on the redirected hop"
    );
}

/// A `Location` is a URI-reference, not necessarily an absolute URL: a
/// relative one resolves against the *request path's directory*, and dot
/// segments are removed before the target is sent. This drives both cases
/// through a real server, because a client that retries the wrong
/// resource is indistinguishable from a working one until it matters.
#[test]
fn client_resolves_relative_redirect_locations() {
    fn handler(
        req: courierust::courierust_http::request::Request<Body>,
    ) -> courierust::courierust_http::response::Response<Body> {
        let target = match req.uri.as_str() {
            "/dir/start" => "next?q=1", // relative path + query
            "/a/b/start" => "../other", // dot segments
            _ => return meta_handler(req),
        };
        let mut resp =
            courierust::courierust_http::response::Response::<Body>::with_status(302.into());
        resp.headers.insert(
            courierust::courierust_http::header::HeaderName::from_lowercase("location"),
            courierust::courierust_http::header::HeaderValue::from_bytes(target.as_bytes())
                .unwrap(),
        );
        resp
    }

    let base = spawn_server(ServerConfig::default(), handler);
    let client = Client::new();

    let resp = client.get(&format!("{base}/dir/start")).unwrap();
    assert_eq!(resp.status.as_u16(), 200);
    assert_eq!(
        resp.headers.get("x-target").unwrap().to_str().unwrap(),
        "/dir/next?q=1",
        "a relative location resolves inside the current directory"
    );

    let resp = client.get(&format!("{base}/a/b/start")).unwrap();
    assert_eq!(resp.status.as_u16(), 200);
    assert_eq!(
        resp.headers.get("x-target").unwrap().to_str().unwrap(),
        "/a/other",
        "dot segments are removed before the target is used"
    );
}

#[test]
fn per_request_timeout_bounds_one_request_only() {
    let base = spawn_server(ServerConfig::default(), |req| {
        if req.uri.as_str() == "/slow" {
            std::thread::sleep(std::time::Duration::from_millis(400));
        }
        let mut resp =
            courierust::courierust_http::response::Response::<Body>::with_status(200.into());
        resp.body = Body::Bytes(Bytes::from_static(b"ok"));
        resp
    });
    let client = Client::new();

    let err = client
        .request(&format!("{base}/slow"), Method::GET)
        .timeout(std::time::Duration::from_millis(50))
        .send()
        .expect_err("the request must not outlive its own deadline");
    assert_eq!(err.kind, courierust::ErrorKind::Timeout, "{err:?}");

    // The connection went back to the pool: it must carry the configured
    // deadline again, not the one that just expired.
    let resp = client.get(&format!("{base}/fast")).unwrap();
    assert_eq!(resp.status.as_u16(), 200);
    assert_eq!(resp.text().unwrap(), "ok");
}

#[test]
fn per_request_timeout_applies_over_h2() {
    let server_cfg = ServerConfig {
        http2: true,
        threads: 2,
        h2_settings_timeout: Some(std::time::Duration::from_secs(60)),
        h2_ping_interval: None,
        h2_ping_timeout: None,
        h2_idle_timeout: None,
        ..Default::default()
    };
    let base = spawn_server(server_cfg, |req| {
        if req.uri.as_str() == "/slow" {
            std::thread::sleep(std::time::Duration::from_millis(400));
        }
        let mut resp =
            courierust::courierust_http::response::Response::<Body>::with_status(200.into());
        resp.body = Body::Bytes(Bytes::from_static(b"ok"));
        resp
    });

    let client = Client::with_config(ClientConfig {
        http2: true,
        h2_settings_timeout: Some(std::time::Duration::from_secs(60)),
        h2_ping_interval: None,
        h2_ping_timeout: None,
        h2_idle_timeout: None,
        ..Default::default()
    });

    let err = client
        .request(&format!("{base}/slow"), Method::GET)
        .timeout(std::time::Duration::from_millis(50))
        .send()
        .expect_err("the h2 stream must be abandoned at its deadline");
    assert_eq!(err.kind, courierust::ErrorKind::Timeout, "{err:?}");

    // Only that stream was abandoned; the connection is still usable.
    let resp = client.get(&format!("{base}/fast")).unwrap();
    assert_eq!(resp.text().unwrap(), "ok");
}

/// A field value with CR, LF or NUL in it must be refused before it goes
/// on the wire, and the error must name the field: over h1 it would split
/// the message, and over h2/h3 it is the value an intermediary would
/// translate into a second message later.
#[test]
fn injected_header_value_is_refused_over_h1_and_h2() {
    let h1_base = spawn_server(ServerConfig::default(), meta_handler);
    let h1 = Client::new();
    let err = h1
        .request(&format!("{h1_base}/a"), Method::GET)
        .header("x-injected", "ok\r\nx-evil: 1")
        .send()
        .expect_err("a CR/LF in a value must be refused");
    assert!(
        err.to_string().contains("header") || err.to_string().contains("x-injected"),
        "the error must point at the field: {err}"
    );

    let server_cfg = ServerConfig {
        http2: true,
        threads: 2,
        h2_settings_timeout: Some(std::time::Duration::from_secs(60)),
        h2_ping_interval: None,
        h2_ping_timeout: None,
        h2_idle_timeout: None,
        ..Default::default()
    };
    let h2_base = spawn_server(server_cfg, meta_handler);
    let h2 = Client::with_config(ClientConfig {
        http2: true,
        h2_settings_timeout: Some(std::time::Duration::from_secs(60)),
        h2_ping_interval: None,
        h2_ping_timeout: None,
        h2_idle_timeout: None,
        ..Default::default()
    });
    let err = h2
        .request(&format!("{h2_base}/a"), Method::GET)
        .header("x-injected", "ok\r\nx-evil: 1")
        .send()
        .expect_err("a CR/LF in a value must be refused over h2 too");
    assert!(
        err.to_string().contains("x-injected"),
        "the error must name the field: {err}"
    );

    // The same field with a legal value still works.
    let resp = h2
        .request(&format!("{h2_base}/a"), Method::GET)
        .header("x-injected", "ok")
        .send()
        .unwrap();
    assert_eq!(resp.status.as_u16(), 200);
}

#[test]
fn response_text_and_bytes_consume_the_body() {
    let base = spawn_server(ServerConfig::default(), |req| {
        let mut resp =
            courierust::courierust_http::response::Response::<Body>::with_status(200.into());
        resp.body = if req.uri.as_str() == "/binary" {
            Body::Bytes(Bytes::from_static(&[0xff, 0xfe]))
        } else {
            Body::Bytes(Bytes::from_static(b"plain text"))
        };
        resp
    });
    let client = Client::new();

    assert_eq!(
        client.get(&format!("{base}/text")).unwrap().text().unwrap(),
        "plain text"
    );
    assert_eq!(
        client
            .get(&format!("{base}/binary"))
            .unwrap()
            .bytes()
            .unwrap(),
        Bytes::from_static(&[0xff, 0xfe])
    );
    let err = client
        .get(&format!("{base}/binary"))
        .unwrap()
        .text()
        .expect_err("a body that is not UTF-8 must not read as text");
    assert_eq!(err.kind, courierust::ErrorKind::Other, "{err:?}");
}

// ---------------------------------------------------------------------
// h1 framing regressions found while building the request-builder tests:
// a HEAD response must carry no content (RFC 9112 §6.3), and an explicit
// `Content-Length: 0` request is complete the moment its headers are.
// ---------------------------------------------------------------------

/// Send raw bytes to a server and return everything it writes back before
/// closing (the caller asks for `Connection: close`).
fn raw_exchange(addr: &str, request: &str) -> String {
    use std::io::{Read, Write};
    let mut stream = std::net::TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(3)))
        .unwrap();
    stream.write_all(request.as_bytes()).unwrap();
    let mut out = Vec::new();
    let _ = stream.read_to_end(&mut out);
    String::from_utf8_lossy(&out).into_owned()
}

#[test]
fn h1_request_with_explicit_zero_content_length_is_answered() {
    let base = spawn_server(ServerConfig::default(), meta_handler);
    let addr = base.trim_start_matches("http://");
    let resp = raw_exchange(
        addr,
        &format!(
            "GET /a HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
        ),
    );
    assert!(
        resp.starts_with("HTTP/1.1 200"),
        "a zero-length body is no body; the request must be answered: {resp:?}"
    );
}

#[test]
fn h1_head_response_carries_headers_but_no_body() {
    let base = spawn_server(ServerConfig::default(), meta_handler);
    let addr = base.trim_start_matches("http://");
    let resp = raw_exchange(
        addr,
        &format!("HEAD /a HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"),
    );
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp:?}");
    assert!(
        resp.contains("x-method: HEAD"),
        "the header fields stay those of the GET response: {resp:?}"
    );
    assert!(
        resp.ends_with("\r\n\r\n"),
        "a HEAD response must end at its header block: {resp:?}"
    );
}

/// RFC 9112 §6.1 / CWE-444: a request carrying both `Transfer-Encoding:
/// chunked` and `Content-Length` is refused with a `400`, and the bytes
/// pipelined behind it are never parsed as a second request — that desync
/// is the whole mechanism of a request-smuggling attack, so the server
/// answers and then drops the connection instead of choosing a framing
/// that a neighbour might not choose.
#[test]
fn h1_rejects_a_request_with_both_framings() {
    let smuggled = "GET /smuggled HTTP/1.1\r\nHost: x\r\n\r\n";
    let request = format!(
        "POST /a HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nContent-Length: 6\r\n\r\n\
         0\r\n\r\n{smuggled}"
    );

    // Both drivers must answer the same way: which one runs depends only
    // on `ServerConfig::event_driven`.
    for event_driven in [true, false] {
        let base = spawn_server(
            ServerConfig {
                event_driven,
                threads: 1,
                ..Default::default()
            },
            meta_handler,
        );
        let addr = base.trim_start_matches("http://");
        let resp = raw_exchange(addr, &request);
        assert!(
            resp.starts_with("HTTP/1.1 400"),
            "both framings must be refused (event_driven={event_driven}): {resp:?}"
        );
        assert!(
            !resp.contains("x-target: /smuggled"),
            "the pipelined bytes must not be served (event_driven={event_driven}): {resp:?}"
        );
        assert!(
            !resp.contains("HTTP/1.1 200"),
            "no request may be answered from that connection (event_driven={event_driven}): {resp:?}"
        );
    }
}

#[test]
fn builder_query_goes_before_the_fragment() {
    let base = spawn_server(ServerConfig::default(), meta_handler);
    let client = Client::new();
    let resp = client
        .request(&format!("{base}/p#section"), Method::GET)
        .query([("page", "2")])
        .send()
        .unwrap();
    assert_eq!(
        resp.headers.get("x-target").unwrap().to_str().unwrap(),
        "/p?page=2",
        "a fragment must not swallow the query string"
    );
}
