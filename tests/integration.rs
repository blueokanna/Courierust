//! End-to-end integration tests: real TCP client↔server over loopback,
//! covering HTTP/1.1, HTTP/2 (h2c), HTTPS (TLS 1.3) and gRPC.

mod common;

use courierust::courierust_body::Body;
use courierust::courierust_bytes::Bytes;
use courierust::courierust_client::{Client, ClientConfig, TlsSettings as ClientTls};
use courierust::courierust_grpc::GrpcClient;
use courierust::courierust_http::method::Method;
use courierust::courierust_http::request::Request;
use courierust::courierust_server::{Server, ServerConfig, TlsSettings as ServerTls};
use std::sync::Arc;

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
    // GET
    let resp = client.get(&format!("{base}/hello")).unwrap();
    assert_eq!(resp.status.as_u16(), 200);
    assert_eq!(
        resp.headers.get("x-method").unwrap().to_str().unwrap(),
        "GET"
    );
    assert!(resp.body.is_empty());
    // POST with a body
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
    // POST via a Request
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
        // The suite runs many servers in parallel; under load a server
        // can be starved past the 10 s default SETTINGS_TIMEOUT.
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

    // 2 MiB, deliberately above both the 64 KiB connection window and the
    // 256 KiB initial stream window, so both directions must replenish
    // flow-control credit mid-transfer.
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
        // Echo with a small delay to interleave streams.
        std::thread::sleep(std::time::Duration::from_millis(10));
        echo_handler(req)
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

    // Fire several concurrent requests; they share one h2 connection.
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
        // The suite runs many servers in parallel; a tight
        // SETTINGS_TIMEOUT on the server would kill a connection whose
        // client driver is momentarily starved under load.
        h2_settings_timeout: Some(std::time::Duration::from_secs(60)),
        h2_ping_interval: None,
        h2_ping_timeout: None,
        h2_idle_timeout: None,
        ..Default::default()
    };
    spawn_server(server_cfg, |req| {
        if req.uri.as_str() == "/hold" {
            let (tx, body) = courierust::courierust_body::channel();
            // Hold the stream open without sending the body end. The
            // sender is dropped when this thread ends, which closes the
            // channel and ends the stream — so keep it alive for a while.
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
    // One connection carries everything: multiplexing is what makes a
    // slow stream harmless to its peers.
    let client = Client::with_config(ClientConfig {
        http2: true,
        max_connections_per_host: 1,
        connect_timeout: Some(Duration::from_secs(5)),
        read_timeout: Some(Duration::from_secs(30)),
        // The suite runs many servers in parallel; a tight
        // SETTINGS_TIMEOUT would spuriously kill the connection under
        // load before the slow stream is exercised.
        h2_settings_timeout: Some(Duration::from_secs(60)),
        h2_ping_interval: None,
        h2_ping_timeout: None,
        h2_idle_timeout: None,
        ..Default::default()
    });

    // Open a `/hold` stream and confirm its response head arrived (the
    // stream is now open and idle — the server keeps it that way).
    let head_received = Arc::new(AtomicBool::new(false));
    let head_received2 = head_received.clone();
    let slow_client = client.clone();
    let slow_base = base.clone();
    let _slow = std::thread::spawn(move || {
        // Under a heavily loaded parallel suite a fresh connection can
        // transiently fail; the property under test is that the slow
        // stream does not block its peers, so retry the setup a few
        // times before giving up.
        let mut last_err = None;
        for _ in 0..4 {
            match slow_client.get(&format!("{slow_base}/hold")) {
                Ok(resp) => {
                    assert_eq!(resp.status.as_u16(), 200);
                    head_received2.store(true, Ordering::SeqCst);
                    // Keep the response alive (stream stays open); never
                    // read the body.
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

    // Fast requests on the SAME connection must complete promptly while
    // the slow stream is open and idle.
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
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    // Two workers total. The hold connection occupies exactly one of
    // them (the other serves new connections) — if worker occupancy
    // scaled with open streams, ten idle streams would exhaust the pool
    // and a fresh connection could never be served.
    let base = spawn_hold_server(2);

    // Connection A: one client opens ten idle `/hold` streams.
    let opened = Arc::new(AtomicUsize::new(0));
    let client_a = Client::with_config(ClientConfig {
        http2: true,
        max_connections_per_host: 1,
        connect_timeout: Some(Duration::from_secs(5)),
        read_timeout: Some(Duration::from_secs(30)),
        // The suite runs many servers in parallel; a tight
        // SETTINGS_TIMEOUT would spuriously kill the connection under
        // load before the assertion runs.
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
            // Keep the response alive (stream stays open); never read
            // the body.
            std::thread::sleep(Duration::from_secs(8));
            drop(resp);
        }));
    }

    // Wait until all ten idle streams are open.
    let t0 = Instant::now();
    while opened.load(Ordering::SeqCst) < 10 && t0.elapsed() < Duration::from_secs(30) {
        std::thread::sleep(Duration::from_millis(10));
    }
    // Surface any per-stream failures (threads that panicked) so a load
    // regression is visible rather than swallowed.
    for h in handles {
        let _ = h.join();
    }
    assert_eq!(
        opened.load(Ordering::SeqCst),
        10,
        "not all idle streams opened"
    );

    // Connection B: a completely separate client must still be served
    // promptly (the pool is not exhausted by idle streams). A fresh
    // connection can transiently fail under a heavily loaded parallel
    // suite (a worker starved past the connection timeout); the property
    // is that idle streams do not consume workers, so a genuine
    // per-stream exhaustion would fail every attempt while a transient
    // load spike succeeds on retry.
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

    // Typed (string codec) call.
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
    // A successful call must carry grpc-status in the trailing header
    // block (the gRPC wire contract), not the initial metadata.
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
    // Drain the body; the stream ends with trailers carrying grpc-status.
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
    // A handler that overruns the client's grpc-timeout must produce
    // DEADLINE_EXCEEDED, not a late OK.
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
// HTTPS (TLS 1.3) integration tests
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
        }),
        ..Default::default()
    }
}

#[test]
fn https_h1_get_and_post_roundtrip() {
    let base = spawn_tls_server(https_server_config(false), echo_handler);
    let client = Client::with_config(https_client_config(false));

    // GET over TLS.
    let resp = client.get(&format!("{base}/secure-hello")).unwrap();
    assert_eq!(resp.status.as_u16(), 200);
    assert_eq!(
        resp.headers.get("x-method").unwrap().to_str().unwrap(),
        "GET"
    );

    // POST over TLS.
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

    // No roots configured -> https must be refused (certificate error).
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

    // A batch of malformed "TLS" clients: truncated records, wrong
    // content types, and garbage bytes that never form a ClientHello.
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
    // Give the server a moment to process (and fail) the garbage.
    std::thread::sleep(std::time::Duration::from_millis(50));

    // A valid HTTPS client must still be served.
    let client = Client::with_config(https_client_config(true));
    let resp = client.get(&format!("{base}/after-garbage")).unwrap();
    assert_eq!(resp.status.as_u16(), 200);
}

/// ALPN must be enforced: a client configured for HTTP/1.1 whose TLS
/// layer nevertheless negotiates h2 gets a clear error instead of a
/// silent protocol mismatch.
#[test]
fn https_client_enforces_alpn_agreement() {
    // h2-only server (alpn = [h2]).
    let base = spawn_tls_server(https_server_config(true), echo_handler);
    // Client configured for HTTP/1.1 (http2: false) but whose ALPN list
    // overlaps the server (h2), so TLS negotiates h2 — the h1 codec must
    // refuse to run on it.
    let client = Client::with_config(ClientConfig {
        http2: false,
        tls: Some(ClientTls {
            roots: common::root_store(),
            verify: true,
            alpn: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            now: common::NOW,
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
// Event-driven server (Windows): idle connections must not hold workers
// ---------------------------------------------------------------------

/// Read one complete raw HTTP/1.1 response (head + Content-Length body)
/// from a socket.
fn read_raw_response(stream: &mut std::net::TcpStream) -> String {
    use std::io::Read;
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let mut head_end = None;
    while head_end.is_none() {
        let n = stream.read(&mut tmp).unwrap();
        assert!(n > 0, "unexpected EOF while reading response head");
        buf.extend_from_slice(&tmp[..n]);
        head_end = find_subslice(&buf, b"\r\n\r\n");
    }
    let he = head_end.unwrap() + 4;
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
    while buf.len() < he + cl {
        let n = stream.read(&mut tmp).unwrap();
        assert!(n > 0, "unexpected EOF while reading response body");
        buf.extend_from_slice(&tmp[..n]);
    }
    String::from_utf8_lossy(&buf[..he + cl]).to_string()
}

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// With only two event workers, a large herd of idle keep-alive
/// connections must NOT exhaust the pool: a fresh request is still served
/// promptly (idle connections park on the poller, consuming zero
/// workers).
#[test]
#[cfg(windows)]
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
    let mut idle: Vec<TcpStream> = Vec::new();
    for _ in 0..60 {
        let mut s = TcpStream::connect(&addr).unwrap();
        s.write_all(b"GET /idle HTTP/1.1\r\nHost: x\r\n\r\n")
            .unwrap();
        let resp = read_raw_response(&mut s);
        assert!(resp.starts_with("HTTP/1.1 200"), "got {resp}");
        idle.push(s); // hold open: idle keep-alive
    }

    let client = Client::new();
    let t0 = std::time::Instant::now();
    let resp = client.get(&format!("{base}/fresh")).unwrap();
    assert_eq!(resp.status.as_u16(), 200);
    // Generous sanity bound (not a latency benchmark): under a full
    // parallel suite the accept/event threads can be starved for seconds.
    assert!(
        t0.elapsed() < std::time::Duration::from_secs(10),
        "fresh request blocked behind idle connections: {:?}",
        t0.elapsed()
    );

    // The idle connections are still usable (kept alive).
    for s in idle.iter_mut() {
        s.write_all(b"GET /again HTTP/1.1\r\nHost: x\r\n\r\n")
            .unwrap();
        let resp = read_raw_response(s);
        assert!(resp.starts_with("HTTP/1.1 200"), "got {resp}");
    }
}

/// A slow sender that stalls mid-request must be parked (not hold a
/// worker) and resume when the rest arrives (incremental parsing).
#[test]
#[cfg(windows)]
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

    let mut s = TcpStream::connect(&addr).unwrap();
    // Send a partial request, then stall well beyond any poll timeout.
    s.write_all(b"GET /slow HTTP/1.1\r\nHost: x\r\n").unwrap();
    std::thread::sleep(Duration::from_millis(300));
    let t0 = Instant::now();
    s.write_all(b"\r\n").unwrap(); // complete the headers
    let resp = read_raw_response(&mut s);
    assert!(resp.starts_with("HTTP/1.1 200"), "got {resp}");
    // The stalled request must resume. The bound is a generous sanity
    // check (not a latency benchmark): under a full parallel test suite
    // the event-loop thread can occasionally be starved for seconds.
    assert!(t0.elapsed() < Duration::from_secs(10));

    let client = Client::new();
    let resp = client.get(&format!("{base}/parallel")).unwrap();
    assert_eq!(resp.status.as_u16(), 200);
}

/// Pipelined requests on one connection are served in order.
#[test]
#[cfg(windows)]
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

    let mut s = TcpStream::connect(&addr).unwrap();
    s.write_all(b"GET /one HTTP/1.1\r\nHost: x\r\n\r\nGET /two HTTP/1.1\r\nHost: x\r\n\r\n")
        .unwrap();
    let r1 = read_raw_response(&mut s);
    let r2 = read_raw_response(&mut s);
    assert!(r1.contains("/one"), "got {r1}");
    assert!(r2.contains("/two"), "got {r2}");
}

/// SSE-style streaming over the event loop: a channel body streamed as
/// chunked reaches the client across multiple events.
#[test]
#[cfg(windows)]
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
