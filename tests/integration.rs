//! End-to-end integration tests: real TCP client↔server over loopback,
//! covering HTTP/1.1, HTTP/2 (h2c) and gRPC.

use courierust::body::Body;
use courierust::bytes::Bytes;
use courierust::client::{Client, ClientConfig};
use courierust::grpc::GrpcClient;
use courierust::http::method::Method;
use courierust::http::request::Request;
use courierust::server::{Server, ServerConfig};
use std::sync::Arc;

/// Spin up an HTTP server on an ephemeral port and return its base URL.
fn spawn_server(
    config: ServerConfig,
    handler: impl Fn(courierust::http::request::Request<Body>) -> courierust::http::response::Response<Body>
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

fn echo_handler(
    req: courierust::http::request::Request<Body>,
) -> courierust::http::response::Response<Body> {
    let mut resp = courierust::http::response::Response::<Body>::with_status(200.into());
    resp.headers.insert(
        courierust::http::header::HeaderName::from_lowercase("x-method"),
        courierust::http::header::HeaderValue::from_bytes(req.method.as_str().as_bytes()).unwrap(),
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
        ..Default::default()
    };
    let base = spawn_server(server_cfg, echo_handler);

    let client_cfg = ClientConfig {
        http2: true,
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

#[test]
fn h2_concurrent_streams_multiplex() {
    let server_cfg = ServerConfig {
        http2: true,
        ..Default::default()
    };
    let base = spawn_server(server_cfg, |req| {
        // Echo with a small delay to interleave streams.
        std::thread::sleep(std::time::Duration::from_millis(10));
        echo_handler(req)
    });

    let client_cfg = ClientConfig {
        http2: true,
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

#[test]
fn h1_chunked_streaming_response() {
    let base = spawn_server(ServerConfig::default(), |_req| {
        let (tx, body) = courierust::body::channel();
        std::thread::spawn(move || {
            for i in 0..5 {
                tx.send(Bytes::from(format!("chunk-{i}"))).unwrap();
            }
        });
        let mut resp = courierust::http::response::Response::<Body>::with_status(200.into());
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
        ..Default::default()
    };
    let base = spawn_server(server_cfg, |_req| {
        let (tx, body) = courierust::body::channel();
        std::thread::spawn(move || {
            for i in 0..8 {
                tx.send(Bytes::from(format!("part-{i}"))).unwrap();
            }
        });
        let mut resp = courierust::http::response::Response::<Body>::with_status(200.into());
        resp.body = body;
        resp
    });
    let client_cfg = ClientConfig {
        http2: true,
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
    let gsrv = courierust::grpc::GrpcServer::bind("127.0.0.1:0", service).unwrap();
    let addr = gsrv.local_addr().unwrap();
    let _handle = gsrv.serve_background().unwrap();

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
            courierust::grpc::status::NOT_FOUND,
            "nope",
        ))
    };
    let gsrv = courierust::grpc::GrpcServer::bind("127.0.0.1:0", service).unwrap();
    let addr = gsrv.local_addr().unwrap();
    let _handle = gsrv.serve_background().unwrap();

    let client = GrpcClient::new(&format!("http://{addr}")).unwrap();
    let err = client.call("/x.Y/Z", Bytes::from_static(b"x")).unwrap_err();
    assert_eq!(err.grpc_code(), Some(courierust::grpc::status::NOT_FOUND));
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
            let mut resp = courierust::http::response::Response::<Body>::with_status(302.into());
            resp.headers.insert(
                courierust::http::header::HeaderName::from_lowercase("location"),
                courierust::http::header::HeaderValue::from_static("/end"),
            );
            resp
        } else {
            let mut resp = courierust::http::response::Response::<Body>::with_status(200.into());
            resp.headers.insert(
                courierust::http::header::HeaderName::from_lowercase("x-final"),
                courierust::http::header::HeaderValue::from_static("yes"),
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
        ..Default::default()
    };
    let base = spawn_server(server_cfg, |_req| {
        let (tx, body) = courierust::body::channel();
        std::thread::spawn(move || {
            let chunk = vec![b'x'; 64 * 1024];
            for _ in 0..16 {
                if tx.send(Bytes::from(chunk.clone())).is_err() {
                    break; // client aborted the stream
                }
            }
        });
        let mut resp = courierust::http::response::Response::<Body>::with_status(200.into());
        resp.body = body;
        resp
    });

    let client_cfg = ClientConfig {
        http2: true,
        max_body: 1024,
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

    // Target server B records whether `Authorization` arrived.
    let base_b = Arc::new(spawn_server(ServerConfig::default(), move |req| {
        let has = req.headers.contains_key("authorization");
        *got_auth_b.lock().unwrap() = has;
        let mut resp = courierust::http::response::Response::<Body>::with_status(200.into());
        resp.body = Body::Bytes(Bytes::from(if has { "has" } else { "none" }));
        resp
    }));

    // Redirector server A: 302 -> B (a different origin/port).
    let location = base_b.to_string();
    let base_a = spawn_server(ServerConfig::default(), move |_req| {
        let mut resp = courierust::http::response::Response::<Body>::with_status(302.into());
        resp.headers.insert(
            courierust::http::header::HeaderName::from_lowercase("location"),
            courierust::http::header::HeaderValue::from_bytes(location.as_bytes()).unwrap(),
        );
        resp
    });

    let client = Client::new();
    let mut req = Request::new(Method::GET, "/");
    req.headers.insert(
        courierust::http::header::HeaderName::from_lowercase("authorization"),
        courierust::http::header::HeaderValue::from_static("Bearer secret"),
    );
    let resp = client.execute(&format!("{base_a}/"), req).unwrap();
    assert_eq!(resp.status.as_u16(), 200);
    assert!(
        !*got_auth.lock().unwrap(),
        "authorization leaked across origins on redirect"
    );
}
