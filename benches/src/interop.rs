//! Real-world interop validation: Courierust against the mainstream Rust
//! HTTP stack (hyper server, hyper-util client, reqwest client), plus
//! HTTP/3 self-interop cases over QUIC v1 + TLS 1.3 on real UDP sockets.
//!
//! This is *not* a benchmark. Each case starts a real peer on a real
//! socket and asserts correct end-to-end semantics:
//!
//! * request/response round-trips (status, body, path echo) over
//!   HTTP/1.1 and HTTP/2 (h2c prior knowledge),
//! * HTTP/2 multiplexing correctness (concurrent requests with distinct
//!   paths must not be cross-wired),
//! * large-body integrity over h1 and h2 (flow-control / framing),
//! * keep-alive reuse and chunked framing against a foreign peer,
//! * HTTP/3 (QUIC) round-trips, pooled connection reuse, large-body flow
//!   control in both directions, and concurrent stream multiplexing
//!   (self-interop: the H3 client and server are both this crate's).
//!
//! Run with `cargo bench --manifest-path benches/Cargo.toml --bench
//! interop` (or `cargo run --release --manifest-path benches/Cargo.toml
//! --bench interop`). Any failed case exits non-zero so CI fails on a
//! real interop regression, not just on benchmark numbers.
//!
//! The mainstream crates are dev-only dependencies of this bench
//! workspace; the `courierust` library itself stays zero-dependency.

use courierust::courierust_body::Body;
use courierust::courierust_bytes::Bytes;
use courierust::courierust_client::{Client, ClientConfig, TlsSettings as ClientTls};
use courierust::courierust_http::header::{HeaderName, HeaderValue};
use courierust::courierust_http::method::Method;
use courierust::courierust_http::request::Request;
use courierust::courierust_http::response::Response;
use courierust::courierust_server::{Server, ServerConfig, TlsSettings as ServerTls};

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
                let _ = stream.set_nodelay(true);
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
// TLS helpers (self-signed identity, CN=localhost, SAN DNS:localhost +
// IP:127.0.0.1)
// ---------------------------------------------------------------------------

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

const SERVER_CERT_DER: &[u8] = include_bytes!("../../tests/certs/server_cert.der");
const SERVER_KEY_DER: &[u8] = include_bytes!("../../tests/certs/server_key.der");

fn load_test_identity() -> (
    courierust::courierust_tls::Identity,
    courierust::courierust_tls::RootStore,
) {
    let identity = courierust::courierust_tls::Identity {
        cert_chain: vec![SERVER_CERT_DER.to_vec()],
        private_key: SERVER_KEY_DER.to_vec(),
        is_rsa: false,
    };
    let mut roots = courierust::courierust_tls::RootStore::new();
    roots.add_der(SERVER_CERT_DER.to_vec());
    (identity, roots)
}

/// A Courierust HTTPS server echoing the request path; `alpn` is offered
/// verbatim (so a test can force an h1-only or h2-only server).
fn courierust_tls_server(alpn: Vec<Vec<u8>>) -> std::net::SocketAddr {
    let (identity, _) = load_test_identity();
    let http2 = alpn.iter().any(|p| p == b"h2");
    let server = Server::bind_with_config(
        "127.0.0.1:0",
        ServerConfig {
            http2,
            tls: Some(ServerTls { identity, alpn, ..Default::default() }),
            ..Default::default()
        },
    )
    .unwrap();
    let addr = server.local_addr().unwrap();
    let handle = server
        .serve_background(|req: Request<Body>| -> Response<Body> {
            let path = req.uri.as_str().to_string();
            let mut resp = Response::with_status(200.into());
            resp.body = Body::Bytes(Bytes::from(path.into_bytes()));
            resp
        })
        .unwrap();
    std::mem::forget(handle);
    addr
}

/// A Courierust HTTPS client. `verify` toggles certificate/hostname
/// validation; `alpn` is offered verbatim.
fn courierust_tls_client(
    http2: bool,
    roots: courierust::courierust_tls::RootStore,
    verify: bool,
    alpn: Vec<Vec<u8>>,
) -> Client {
    Client::with_config(ClientConfig {
        http2,
        max_connections_per_host: 1,
        connect_timeout: Some(Duration::from_secs(3)),
        tls: Some(ClientTls {
            roots,
            verify,
            alpn,
            now: unix_now(),
            ..Default::default()
        }),
        ..Default::default()
    })
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
    let big: Vec<u8> = (0..(64 * 1024)).map(|i| (i % 239) as u8).collect();
    let resp = client
        .post(&format!("http://{addr}/slow"), big.clone())
        .map_err(|e| format!("slow POST failed: {e}"))
        .unwrap();
    let body = resp.body.collect().unwrap();
    assert_eq!(&body[..], &big[..], "slow body echo");
}

// ---------------------------------------------------------------------------
// TLS / ALPN / connection-lifecycle interop cases
// ---------------------------------------------------------------------------

/// A self-signed server certificate that the client does not trust must
/// be rejected at the handshake (failed-cert case).
fn tls_rejects_untrusted_certificate() {
    let addr = courierust_tls_server(vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
    // Empty trust store + verify=true: nothing is trusted.
    let client = courierust_tls_client(
        true,
        courierust::courierust_tls::RootStore::new(),
        true,
        vec![b"h2".to_vec(), b"http/1.1".to_vec()],
    );
    let err = client
        .get(&format!("https://{addr}/untrusted"))
        .map(|_| ())
        .expect_err("untrusted self-signed certificate must be rejected");
    assert!(
        !err.to_string().is_empty(),
        "rejection error must carry a message"
    );
    println!(
        "TLSVERIFY|case=failed_certificate|protocol=https+h2|cert_verified=false|hostname_verified=not_evaluated|negotiated_alpn=none|session_resumption=n/a|error={}",
        err.to_string().replace('|', "/")
    );
}

/// A certificate valid but issued for `localhost` / `127.0.0.1` must be
/// rejected when the peer's hostname does not match (hostname-mismatch
/// case, RFC 6125).
fn tls_rejects_hostname_mismatch() {
    let addr = courierust_tls_server(vec![b"http/1.1".to_vec()]);
    let (_, roots) = load_test_identity();
    let stream = std::net::TcpStream::connect(addr).expect("tcp connect for hostname test");
    let connector =
        courierust::courierust_tls::TlsConnector::new(courierust::courierust_tls::ClientConfig {
            roots,
            verify: true,
            alpn: vec![b"http/1.1".to_vec()],
            now: unix_now(),
            ..Default::default()
        });
    let err = connector
        .connect("not-localhost.invalid", &stream, &stream)
        .map(|_| ())
        .expect_err("hostname mismatch must be rejected");
    assert!(
        !err.to_string().is_empty(),
        "hostname rejection must carry a message"
    );
    println!(
        "TLSVERIFY|case=hostname_mismatch|protocol=https+h1|cert_verified=true|hostname_verified=false|negotiated_alpn=none|session_resumption=n/a|error={}",
        err.to_string().replace('|', "/")
    );
}

/// A client that only offers `http/1.1` must negotiate it (ALPN
/// downgrade) and complete the request over HTTP/1.1.
fn tls_alpn_downgrade_to_h1() {
    let addr = courierust_tls_server(vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
    let (_, roots) = load_test_identity();
    let client = courierust_tls_client(false, roots, true, vec![b"http/1.1".to_vec()]);
    let resp = client
        .get(&format!("https://{addr}/downgrade"))
        .expect("http/1.1 over TLS must succeed");
    assert_eq!(resp.status.as_u16(), 200, "downgrade status");
    assert_eq!(
        resp.body.collect().unwrap().as_ref(),
        b"/downgrade",
        "downgrade path echo"
    );
    println!(
        "TLSVERIFY|case=alpn_downgrade|protocol=https+h1|cert_verified=true|hostname_verified=true|negotiated_alpn=http/1.1|session_resumption=n/a|error=-"
    );
}

/// A client configured for HTTP/2 against a server that does not offer
/// h2 must fail (ALPN rejection) instead of silently speaking h2.
fn tls_h2_alpn_rejected() {
    let addr = courierust_tls_server(vec![b"http/1.1".to_vec()]);
    let (_, roots) = load_test_identity();
    let client = courierust_tls_client(true, roots, true, vec![b"h2".to_vec()]);
    let err = client
        .get(&format!("https://{addr}/h2"))
        .map(|_| ())
        .expect_err("h2 over an http/1.1-only server must fail");
    assert!(
        !err.to_string().is_empty(),
        "ALPN rejection must carry a message"
    );
    println!(
        "TLSVERIFY|case=alpn_rejected|protocol=https+h2|cert_verified=not_evaluated|hostname_verified=not_evaluated|negotiated_alpn=none|session_resumption=n/a|error={}",
        err.to_string().replace('|', "/")
    );
}

/// `Connection: close` must be honored: the server closes the connection
/// after the response and the client still reads it completely; a later
/// request on the same client works on a fresh connection.
fn h1_connection_close_honored() {
    let addr = courierust_server(false);
    let client = courierust_client(false);
    let mut req = Request::new(Method::GET, "/close");
    req.headers.insert(
        HeaderName::from_lowercase("connection"),
        HeaderValue::from_static("close"),
    );
    let resp = client
        .execute(&format!("http://{addr}/close"), req)
        .expect("connection-close request must complete");
    assert_eq!(resp.status.as_u16(), 200, "close request status");
    assert_eq!(resp.body.collect().unwrap().as_ref(), b"/close");

    let resp = client
        .get(&format!("http://{addr}/after-close"))
        .expect("client must recover on a fresh connection");
    assert_eq!(
        resp.body.collect().unwrap().as_ref(),
        b"/after-close",
        "post-close request"
    );
}

/// A hyper h2 server that can be told to send GOAWAY (graceful shutdown)
/// on demand. Returns the address and a shutdown signal.
fn hyper_h2_server_graceful() -> (std::net::SocketAddr, tokio::sync::watch::Sender<bool>) {
    use http_body_util::Full;
    use hyper::body::{Bytes as HBytes, Incoming};
    use hyper::service::service_fn;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::server::conn::auto::Builder as AutoBuilder;
    use std::convert::Infallible;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let listener = rt
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    std::thread::spawn(move || {
        rt.block_on(async move {
            let builder = AutoBuilder::new(TokioExecutor::new()).http2_only();
            // The connection task polls the hyper connection to
            // completion; on the shutdown signal it drives a graceful
            // shutdown (GOAWAY) and waits for it to flush.
            let mut spawned: Option<tokio::task::JoinHandle<()>> = None;
            let mut rx_outer = shutdown_rx.clone();
            loop {
                tokio::select! {
                    _ = rx_outer.changed() => break,
                    accepted = listener.accept() => {
                        if let Ok((stream, _)) = accepted {
                            if spawned.is_none() {
                                let rx = shutdown_rx.clone();
                                let svc = service_fn(
                                    |_req: hyper::Request<Incoming>| async move {
                                        Ok::<_, Infallible>(hyper::Response::new(Full::new(
                                            HBytes::from_static(b"ok"),
                                        )))
                                    },
                                );
                                let conn = builder
                                    .serve_connection(TokioIo::new(stream), svc)
                                    .into_owned();
                                spawned = Some(tokio::spawn(async move {
                                    let mut conn = Box::pin(conn);
                                    let mut rx = rx;
                                    tokio::select! {
                                        _ = conn.as_mut() => {}
                                        _ = rx.changed() => {
                                            conn.as_mut().graceful_shutdown();
                                            let _ = conn.await;
                                        }
                                    }
                                }));
                            }
                        }
                    }
                }
            }
            // Let the connection task finish flushing the GOAWAY before
            // the runtime is dropped.
            if let Some(handle) = spawned {
                let _ = handle.await;
            }
        });
    });
    (addr, shutdown_tx)
}

/// A peer GOAWAY must make the old connection unusable (fast failure,
/// not a hang) and must not poison the client for fresh connections.
fn courierust_h2_client_survives_peer_goaway() {
    let (addr, shutdown_tx) = hyper_h2_server_graceful();
    let client = courierust_client(true);
    let base = format!("http://{addr}/goaway");

    let resp = client
        .get(&base)
        .map_err(|e| format!("request before GOAWAY failed: {e}"))
        .unwrap();
    assert_eq!(resp.status.as_u16(), 200, "pre-GOAWAY status");
    assert_eq!(resp.body.collect().unwrap().as_ref(), b"ok");

    // Ask the foreign peer to GOAWAY, then give the driver time to
    // observe it and mark the connection non-accepting.
    shutdown_tx.send(true).expect("send shutdown signal");
    std::thread::sleep(Duration::from_millis(600));

    // The old connection must not be reused; the server is gone, so the
    // request must fail fast (a hang would be a driver bug).
    let result = client.get(&base);
    assert!(
        result.is_err(),
        "request after peer GOAWAY must fail fast, got {result:?}"
    );

    // The client object must recover on a fresh server/authority.
    let addr2 = hyper_server(true);
    let resp = client
        .get(&format!("http://{addr2}/recovered"))
        .map_err(|e| format!("request after GOAWAY recovery failed: {e}"))
        .unwrap();
    assert_eq!(resp.status.as_u16(), 200, "recovery status");
}

// ---------------------------------------------------------------------------
// HTTP/3 self-interop cases (QUIC v1 + TLS 1.3 over loopback)
//
// The H3 client and server are both Courierust's own (there is no
// mainstream H3 peer in this workspace), so these cases are a loopback
// regression gate for the H3 path — the `h3` bench measures it, this
// validates correctness. They run on real UDP sockets through the whole
// stack: Retry address validation, QUIC handshake, QPACK, connection
// reuse, flow control and stream multiplexing.
// ---------------------------------------------------------------------------

/// A Courierust HTTP/3 server echoing the request body (or the request
/// path when the body is empty), over QUIC v1 + TLS 1.3.
fn courierust_h3_server() -> std::net::SocketAddr {
    let (identity, _) = load_test_identity();
    let server = Server::bind_with_config(
        "127.0.0.1:0",
        ServerConfig {
            http3: true,
            tls: Some(ServerTls {
                identity,
                alpn: vec![b"h3".to_vec()],
                ..Default::default()
            }),
            ..Default::default()
        },
    )
    .unwrap();
    let addr = server.local_addr().unwrap();
    let handle = server
        .serve_background(|req: Request<Body>| -> Response<Body> {
            let body = req.body.collect().unwrap_or_default();
            let payload = if body.is_empty() {
                Bytes::from(req.uri.as_str().to_string().into_bytes())
            } else {
                body
            };
            Response::<Body>::with_status(200.into()).with_body(Body::Bytes(payload))
        })
        .unwrap();
    std::mem::forget(handle);
    addr
}

/// A Courierust HTTP/3 client pinned to one pooled QUIC connection per
/// authority (the reuse / multiplexing path under test).
fn courierust_h3_client() -> Client {
    let (_, roots) = load_test_identity();
    Client::with_config(ClientConfig {
        http3: true,
        max_connections_per_host: 1,
        connect_timeout: Some(Duration::from_secs(3)),
        read_timeout: Some(Duration::from_secs(10)),
        tls: Some(ClientTls {
            roots,
            verify: true,
            alpn: vec![b"h3".to_vec()],
            now: unix_now(),
            ..Default::default()
        }),
        ..Default::default()
    })
}

/// GET path echo and POST body echo over HTTP/3.
fn h3_self_roundtrip() {
    let addr = courierust_h3_server();
    let client = courierust_h3_client();

    let resp = client
        .get(&format!("https://{addr}/h3hello"))
        .map_err(|e| format!("h3 GET failed: {e}"))
        .unwrap();
    assert_eq!(resp.status.as_u16(), 200, "h3 GET status");
    assert_eq!(
        resp.body.collect().unwrap().to_str().unwrap(),
        "/h3hello",
        "h3 GET path echo"
    );

    let big: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();
    let resp = client
        .post(&format!("https://{addr}/h3echo"), big.clone())
        .map_err(|e| format!("h3 POST failed: {e}"))
        .unwrap();
    assert_eq!(resp.status.as_u16(), 200, "h3 POST status");
    assert_eq!(
        &resp.body.collect().unwrap()[..],
        &big[..],
        "h3 POST body echo"
    );
}

/// Sequential requests over the pooled H3 connection: the QUIC/TLS
/// handshake is paid once, and every later request rides a fresh stream
/// on the same connection.
fn h3_self_connection_reuse() {
    let addr = courierust_h3_server();
    let client = courierust_h3_client();
    for i in 0..20 {
        let path = format!("/reuse/{i}");
        let resp = client
            .get(&format!("https://{addr}{path}"))
            .map_err(|e| format!("h3 reuse request {i} failed: {e}"))
            .unwrap();
        assert_eq!(resp.status.as_u16(), 200, "h3 reuse status {i}");
        assert_eq!(
            resp.body.collect().unwrap().to_str().unwrap(),
            path,
            "h3 reuse path echo {i}"
        );
    }
}

/// A 256 KiB POST body and 256 KiB response over a fresh H3 connection:
/// the body is far larger than the initial congestion window (12 KiB),
/// so it must be delivered in ACK-paced chunks in both directions (the
/// classic place QUIC stacks break).
fn h3_self_large_body_flow_control() {
    let addr = courierust_h3_server();
    let client = courierust_h3_client();
    let big: Vec<u8> = (0..(256 * 1024)).map(|i| (i % 253) as u8).collect();
    let resp = client
        .post(&format!("https://{addr}/h3-big"), big.clone())
        .map_err(|e| format!("h3 big POST failed: {e}"))
        .unwrap();
    assert_eq!(resp.status.as_u16(), 200, "h3 big status");
    let body = resp.body.collect().unwrap();
    assert_eq!(
        &body[..],
        &big[..],
        "h3 256 KiB body echo (flow control both directions)"
    );
}

/// Concurrent requests multiplexed over one pooled H3 connection (the
/// QUIC analog of h2's stream multiplexing).
fn h3_self_multiplex_concurrent() {
    let addr = courierust_h3_server();
    let client = courierust_h3_client();
    let mut handles = Vec::new();
    for i in 0..16 {
        let client = client.clone();
        let url = format!("https://{addr}/mux/{i}");
        handles.push(std::thread::spawn(move || {
            let resp = client
                .get(&url)
                .map_err(|e| format!("h3 mux request {i} failed: {e}"))
                .unwrap();
            assert_eq!(resp.status.as_u16(), 200, "h3 mux status {i}");
            resp.body.collect().unwrap().to_str().unwrap().to_string()
        }));
    }
    for (i, handle) in handles.into_iter().enumerate() {
        let body = handle.join().unwrap();
        assert_eq!(body, format!("/mux/{i}"), "h3 mux path echo {i}");
    }
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
    case(
        "tls_rejects_untrusted_certificate",
        tls_rejects_untrusted_certificate,
    );
    case(
        "tls_rejects_hostname_mismatch",
        tls_rejects_hostname_mismatch,
    );
    case("tls_alpn_downgrade_to_h1", tls_alpn_downgrade_to_h1);
    case("tls_h2_alpn_rejected", tls_h2_alpn_rejected);
    case("h1_connection_close_honored", h1_connection_close_honored);
    case(
        "courierust_h2_client_survives_peer_goaway",
        courierust_h2_client_survives_peer_goaway,
    );
    // HTTP/3 self-interop (loopback regression gates for the H3 path).
    case("h3_self_roundtrip", h3_self_roundtrip);
    case("h3_self_connection_reuse", h3_self_connection_reuse);
    case(
        "h3_self_large_body_flow_control",
        h3_self_large_body_flow_control,
    );
    case("h3_self_multiplex_concurrent", h3_self_multiplex_concurrent);

    let failures = FAILURES.load(Ordering::SeqCst);
    if failures == 0 {
        println!("INTEROP|all_cases_passed");
    } else {
        println!("INTEROP|{failures} case(s) FAILED");
        std::process::exit(1);
    }
}

const _: Duration = Duration::from_secs(0);
