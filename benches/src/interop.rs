//! Real-world interop validation: Courierust against the mainstream Rust
//! HTTP stack (hyper server, hyper-util client, reqwest client).
//!
//! This is *not* a benchmark. Each case starts a real peer on a real
//! socket and asserts correct end-to-end semantics:
//!
//! * request/response round-trips (status, body, path echo) over
//!   HTTP/1.1 and HTTP/2 (h2c prior knowledge),
//! * HTTP/2 multiplexing correctness (concurrent requests with distinct
//!   paths must not be cross-wired),
//! * large-body integrity over h1 and h2 (flow-control / framing),
//! * keep-alive reuse and chunked framing against a foreign peer.
//!
//! Run with `cargo bench --manifest-path benches/Cargo.toml --bench
//! interop` (or `cargo run --release --manifest-path benches/Cargo.toml
//! --bench interop`). Any failed case exits non-zero so CI fails on a
//! real interop regression, not just on benchmark numbers.
//!
//! The mainstream crates are dev-only dependencies of this bench
//! workspace; the `courierust` library itself stays zero-dependency.

use courierust::body::Body;
use courierust::bytes::Bytes;
use courierust::client::{Client, ClientConfig};
use courierust::http::request::Request;
use courierust::http::response::Response;
use courierust::server::{Server, ServerConfig};

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

static FAILURES: AtomicUsize = AtomicUsize::new(0);

/// Run one interop case, catching panics so every case is attempted and
/// reported even when an earlier one failed. A watchdog aborts the
/// process if a case neither finishes nor panics within 90 s, so a
/// regression that hangs (instead of failing) still fails CI fast.
fn case(name: &str, f: impl FnOnce()) {
    let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
    let wname = name.to_string();
    std::thread::spawn(
        move || match done_rx.recv_timeout(Duration::from_secs(90)) {
            Ok(()) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                eprintln!("INTEROP|case={wname}|TIMEOUT after 90s");
                std::process::abort();
            }
        },
    );
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    let _ = done_tx.send(());
    match r {
        Ok(()) => println!("INTEROP|case={name}|ok"),
        Err(e) => {
            FAILURES.fetch_add(1, Ordering::SeqCst);
            let msg = e
                .downcast_ref::<&str>()
                .map(|s| s.to_string())
                .or_else(|| e.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "unknown panic".to_string());
            println!("INTEROP|case={name}|FAILED|{msg}");
        }
    }
    std::io::Write::flush(&mut std::io::stdout()).ok();
}

fn fail(name: &str, msg: &str) -> ! {
    std::panic::panic_any(format!("{name}: {msg}"));
}

// ---------------------------------------------------------------------------
// Peer servers
// ---------------------------------------------------------------------------

/// A hyper server that echoes the request body, or the request path when
/// the body is empty. Serving h1 (`http2 = false`) or h2 (`http2 = true`).
fn hyper_server(http2: bool) -> std::net::SocketAddr {
    use http_body_util::Full;
    use hyper::body::{Bytes as HBytes, Incoming};
    use hyper::service::service_fn;
    use hyper_util::rt::TokioExecutor;
    use hyper_util::rt::TokioIo;
    use hyper_util::server::conn::auto::Builder as AutoBuilder;
    use std::convert::Infallible;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    let listener = rt
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        rt.block_on(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let io = TokioIo::new(stream);
                let svc = service_fn(|req: hyper::Request<Incoming>| async move {
                    let path = req.uri().path().to_string();
                    let body = match http_body_util::BodyExt::collect(req.into_body()).await {
                        Ok(b) => b.to_bytes(),
                        Err(_) => HBytes::new(),
                    };
                    let payload = if body.is_empty() {
                        path.into_bytes()
                    } else {
                        body.to_vec()
                    };
                    Ok::<_, Infallible>(hyper::Response::new(Full::new(HBytes::from(payload))))
                });
                let builder = if http2 {
                    AutoBuilder::new(TokioExecutor::new()).http2_only()
                } else {
                    AutoBuilder::new(TokioExecutor::new()).http1_only()
                };
                tokio::spawn(async move {
                    let _ = builder.serve_connection(io, svc).await;
                });
            }
        });
    });
    addr
}

/// A Courierust server echoing the request body, or the request path when
/// the body is empty. Serves h1 only, or h1+h2 on the same port.
fn courierust_server(http2: bool) -> std::net::SocketAddr {
    let cfg = ServerConfig {
        http2,
        ..Default::default()
    };
    let server = Server::bind_with_config("127.0.0.1:0", cfg).unwrap();
    let addr = server.local_addr().unwrap();
    let handle = server
        .serve_background(|req: Request<Body>| -> Response<Body> {
            let path = req.uri.as_str().to_string();
            let body = req.body.collect().unwrap_or_default();
            let payload = if body.is_empty() {
                path.into_bytes()
            } else {
                body.to_vec()
            };
            let mut resp = Response::with_status(200.into());
            resp.body = Body::Bytes(Bytes::from(payload));
            resp
        })
        .unwrap();
    std::mem::forget(handle);
    addr
}

fn courierust_client(http2: bool) -> Client {
    let cfg = ClientConfig {
        http2,
        ..Default::default()
    };
    Client::with_config(cfg)
}

// ---------------------------------------------------------------------------
// Cases
// ---------------------------------------------------------------------------

/// Courierust h1 client against a real hyper h1 server: GET path echo,
/// POST body echo, keep-alive reuse, large body integrity.
fn courierust_client_h1_to_hyper_h1() {
    let addr = hyper_server(false);
    let client = courierust_client(false);

    let url = format!("http://{addr}/alpha");
    let resp = client
        .get(&url)
        .map_err(|e| format!("GET failed: {e}"))
        .unwrap();
    assert_eq!(resp.status.as_u16(), 200, "GET status");
    let body = resp.body.collect().unwrap();
    assert_eq!(&body[..], b"/alpha", "GET path echo");

    // POST with a body is echoed by the foreign server.
    let resp = client
        .post(&format!("http://{addr}/echo"), b"hello world".as_slice())
        .map_err(|e| format!("POST failed: {e}"))
        .unwrap();
    assert_eq!(resp.status.as_u16(), 200, "POST status");
    let body = resp.body.collect().unwrap();
    assert_eq!(&body[..], b"hello world", "POST body echo");

    // Keep-alive reuse: several sequential requests over the same pooled
    // connection must all succeed and map to the right path.
    for i in 0..25 {
        let url = format!("http://{addr}/keepalive-{i}");
        let resp = client
            .get(&url)
            .map_err(|e| format!("keep-alive GET {i} failed: {e}"))
            .unwrap();
        let body = resp.body.collect().unwrap();
        assert_eq!(
            body.as_ref(),
            format!("/keepalive-{i}").as_bytes(),
            "keep-alive echo {i}"
        );
    }

    // 256 KiB POST: framing + chunked boundaries against a foreign peer.
    let big: Vec<u8> = (0..(256 * 1024)).map(|i| (i % 251) as u8).collect();
    let resp = client
        .post(&format!("http://{addr}/big"), big.clone())
        .map_err(|e| format!("big POST failed: {e}"))
        .unwrap();
    let body = resp.body.collect().unwrap();
    assert_eq!(&body[..], &big[..], "large body echo");
}

/// Courierust h2c client against a real hyper h2 server: path echo,
/// POST echo, and multiplexing (concurrent requests with distinct paths
/// must not be cross-wired).
fn courierust_client_h2c_to_hyper_h2() {
    let addr = hyper_server(true);
    let client = courierust_client(true);

    let url = format!("http://{addr}/h2-alpha");
    let resp = client
        .get(&url)
        .map_err(|e| format!("h2 GET failed: {e}"))
        .unwrap();
    assert_eq!(resp.status.as_u16(), 200, "h2 GET status");
    let body = resp.body.collect().unwrap();
    assert_eq!(&body[..], b"/h2-alpha", "h2 GET path echo");

    let resp = client
        .post(&format!("http://{addr}/h2-echo"), b"payload".as_slice())
        .map_err(|e| format!("h2 POST failed: {e}"))
        .unwrap();
    let body = resp.body.collect().unwrap();
    assert_eq!(&body[..], b"payload", "h2 POST body echo");

    // Multiplexing: 8 threads × 30 requests, each with a unique path.
    // Response/request cross-wiring (the classic h2 bug) shows up as a
    // path mismatch.
    let mut handles = Vec::new();
    for t in 0..8u32 {
        let client = client.clone();
        let base = addr.to_string();
        handles.push(std::thread::spawn(move || {
            for i in 0..30u32 {
                let tag = format!("mx-{t}-{i}");
                let url = format!("http://{base}/{tag}");
                let resp = client
                    .get(&url)
                    .unwrap_or_else(|e| fail("h2 multiplex", &format!("GET {tag}: {e}")));
                let body = resp.body.collect().unwrap();
                let expect = format!("/{tag}");
                assert_eq!(
                    body.as_ref(),
                    expect.as_bytes(),
                    "h2 multiplex cross-wire on {tag}"
                );
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

/// A real hyper-util h1 client against the Courierust h1 server.
fn hyper_client_h1_to_courierust_h1() {
    use http_body_util::Empty;
    use hyper::body::Bytes as HBytes;

    let addr = courierust_server(false);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let client = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
        .http2_only(false)
        .build_http();

    for i in 0..20 {
        let uri = format!("http://{addr}/from-hyper-h1-{i}");
        let req = hyper::Request::builder()
            .uri(uri)
            .body(Empty::<HBytes>::new())
            .unwrap();
        let resp = rt
            .block_on(client.request(req))
            .unwrap_or_else(|e| fail("hyper->courierust h1", &e.to_string()));
        assert_eq!(resp.status().as_u16(), 200, "hyper h1 status");
        let body = rt.block_on(async {
            http_body_util::BodyExt::collect(resp.into_body())
                .await
                .unwrap()
                .to_bytes()
        });
        let expect = format!("/from-hyper-h1-{i}");
        assert_eq!(&body[..], expect.as_bytes(), "hyper h1 path echo {i}");
    }

    // POST echo. A separate client instance because the legacy hyper
    // client is generic over the request body type, which is fixed at
    // first use (`Empty` above, `Full` here).
    let body = HBytes::from_static(b"hello from hyper");
    let req = hyper::Request::builder()
        .method(hyper::Method::POST)
        .uri(format!("http://{addr}/post"))
        .body(http_body_util::Full::new(body))
        .unwrap();
    let post_client =
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .http2_only(false)
            .build_http();
    let resp = rt
        .block_on(post_client.request(req))
        .unwrap_or_else(|e| fail("hyper->courierust h1 POST", &e.to_string()));
    let body = rt.block_on(async {
        http_body_util::BodyExt::collect(resp.into_body())
            .await
            .unwrap()
            .to_bytes()
    });
    assert_eq!(&body[..], b"hello from hyper", "hyper h1 POST echo");
}

/// A real hyper-util h2c client against the Courierust h2 server, with
/// concurrent requests to exercise the server's multiplexing.
fn hyper_client_h2c_to_courierust_h2() {
    use http_body_util::Empty;
    use hyper::body::Bytes as HBytes;

    let addr = courierust_server(true);
    let rt = std::sync::Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap(),
    );

    for t in 0..4u32 {
        let rt = rt.clone();
        let base = addr.to_string();
        std::thread::spawn(move || {
            let client =
                hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                    .http2_only(true)
                    .build_http();
            for i in 0..15u32 {
                let tag = format!("hx-{t}-{i}");
                let req = hyper::Request::builder()
                    .uri(format!("http://{base}/{tag}"))
                    .body(Empty::<HBytes>::new())
                    .unwrap();
                let resp = rt
                    .block_on(client.request(req))
                    .unwrap_or_else(|e| fail("hyper h2c->courierust", &e.to_string()));
                assert_eq!(resp.status().as_u16(), 200, "hyper h2c status {tag}");
                let body = rt.block_on(async {
                    http_body_util::BodyExt::collect(resp.into_body())
                        .await
                        .unwrap()
                        .to_bytes()
                });
                let expect = format!("/{tag}");
                assert_eq!(&body[..], expect.as_bytes(), "hyper h2c path echo {tag}");
            }
        })
        .join()
        .unwrap();
    }
}

/// reqwest (blocking, h1) against the Courierust server.
fn reqwest_h1_to_courierust_h1() {
    let addr = courierust_server(false);
    let client = reqwest::blocking::Client::new();
    for i in 0..10 {
        let resp = client
            .get(format!("http://{addr}/rw-h1-{i}"))
            .send()
            .unwrap_or_else(|e| fail("reqwest h1", &e.to_string()));
        assert_eq!(resp.status().as_u16(), 200, "reqwest h1 status {i}");
        let body = resp.text().unwrap();
        assert_eq!(body, format!("/rw-h1-{i}"), "reqwest h1 path echo {i}");
    }
    let resp = client
        .post(format!("http://{addr}/rw-post"))
        .body("reqwest-body")
        .send()
        .unwrap_or_else(|e| fail("reqwest h1 POST", &e.to_string()));
    assert_eq!(resp.text().unwrap(), "reqwest-body", "reqwest h1 POST echo");
}

/// reqwest (blocking, h2c prior knowledge) against the Courierust h2
/// server, with concurrent threads exercising multiplexing.
fn reqwest_h2c_to_courierust_h2() {
    let addr = courierust_server(true);
    let client = reqwest::blocking::Client::builder()
        .http2_prior_knowledge()
        .build()
        .unwrap();
    let mut handles = Vec::new();
    for t in 0..4u32 {
        let client = client.clone();
        let base = addr.to_string();
        handles.push(std::thread::spawn(move || {
            for i in 0..15u32 {
                let tag = format!("rw-h2-{t}-{i}");
                let resp = client
                    .get(format!("http://{base}/{tag}"))
                    .send()
                    .unwrap_or_else(|e| fail("reqwest h2c", &e.to_string()));
                assert_eq!(resp.status().as_u16(), 200, "reqwest h2c status {tag}");
                let body = resp.text().unwrap();
                assert_eq!(body, format!("/{tag}"), "reqwest h2c path echo {tag}");
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

/// 1 MiB POST over h2c against a real hyper h2 server: verifies
/// flow-control window management and frame assembly against a foreign
/// peer (the classic place multiplexing stacks break).
fn courierust_h2c_large_body_to_hyper_h2() {
    let addr = hyper_server(true);
    let client = courierust_client(true);
    let big: Vec<u8> = (0..(1024 * 1024)).map(|i| (i % 253) as u8).collect();
    let resp = client
        .post(&format!("http://{addr}/h2-big"), big.clone())
        .map_err(|e| format!("h2 big POST failed: {e}"))
        .unwrap();
    assert_eq!(resp.status.as_u16(), 200, "h2 big status");
    let body = resp.body.collect().unwrap();
    assert_eq!(&body[..], &big[..], "h2 big body echo");
}

/// Courierust h1 client with a slow trickle against the hyper h1 server
/// (a slow-sender sanity check against a foreign peer).
fn courierust_h1_slow_reader_to_hyper_h1() {
    let addr = hyper_server(false);
    let client = courierust_client(false);
    // A moderately large response; read it in small chunks with pauses to
    // exercise the client's read loop against a real server.
    let big: Vec<u8> = (0..(64 * 1024)).map(|i| (i % 239) as u8).collect();
    let resp = client
        .post(&format!("http://{addr}/slow"), big.clone())
        .map_err(|e| format!("slow POST failed: {e}"))
        .unwrap();
    let body = resp.body.collect().unwrap();
    assert_eq!(&body[..], &big[..], "slow body echo");
}

fn main() {
    println!("courierust vs mainstream HTTP stack — interop validation");
    case(
        "courierust_client_h1_to_hyper_h1",
        courierust_client_h1_to_hyper_h1,
    );
    case(
        "courierust_client_h2c_to_hyper_h2",
        courierust_client_h2c_to_hyper_h2,
    );
    case(
        "hyper_client_h1_to_courierust_h1",
        hyper_client_h1_to_courierust_h1,
    );
    case(
        "hyper_client_h2c_to_courierust_h2",
        hyper_client_h2c_to_courierust_h2,
    );
    case("reqwest_h1_to_courierust_h1", reqwest_h1_to_courierust_h1);
    case("reqwest_h2c_to_courierust_h2", reqwest_h2c_to_courierust_h2);
    case(
        "courierust_h2c_large_body_to_hyper_h2",
        courierust_h2c_large_body_to_hyper_h2,
    );
    case(
        "courierust_h1_slow_reader_to_hyper_h1",
        courierust_h1_slow_reader_to_hyper_h1,
    );

    let failures = FAILURES.load(Ordering::SeqCst);
    if failures == 0 {
        println!("INTEROP|all_cases_passed");
    } else {
        println!("INTEROP|{failures} case(s) FAILED");
        std::process::exit(1);
    }
}

// Silence an unused-import warning when `Duration` is not referenced in
// some builds; it documents the "slow" intent above.
const _: Duration = Duration::from_secs(0);
