//! Forward-proxy behaviour: how the client addresses a proxy, and what a
//! proxy is allowed to learn.
//!
//! The proxy here is the simplest thing that deserves the name — it records
//! what it was asked for and then moves bytes — because the subject of
//! these tests is the client's conformance to what a proxy expects to
//! receive, not the proxy itself.

mod common;

use courierust::courierust_body::Body;
use courierust::courierust_client::{Client, ClientConfig, TlsSettings as ClientTls};
use courierust::courierust_http::request::Request;
use courierust::courierust_http::response::Response;
use courierust::courierust_server::{Server, ServerConfig, TlsSettings as ServerTls};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// Read one CRLF-terminated head, a byte at a time.
///
/// A buffered read would consume bytes *past* the head, and past a
/// `200 Connection Established` those bytes are the beginning of the
/// tunnel — one stray `read` here would corrupt the TLS handshake it is
/// carrying. A real proxy parses incrementally for the same reason.
fn read_head(stream: &mut TcpStream) -> Vec<u8> {
    let mut head = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    loop {
        match stream.read(&mut byte) {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                head.push(byte[0]);
                if head.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
        }
    }
    head
}

fn reply(stream: &mut TcpStream, line: &str) {
    let _ = stream.write_all(format!("{line}\r\nContent-Length: 0\r\n\r\n").as_bytes());
    let _ = stream.flush();
}

/// Pipe `from` into `to` until either side goes away, both ways.
fn splice(a: TcpStream, b: TcpStream) {
    let (mut a_read, mut b_write) = (a.try_clone().expect("clone"), b.try_clone().expect("clone"));
    std::thread::spawn(move || {
        let _ = std::io::copy(&mut a_read, &mut b_write);
    });
    let mut b_read = b;
    let mut a_write = a;
    let _ = std::io::copy(&mut b_read, &mut a_write);
}

fn handle(mut client: TcpStream, seen: Arc<Mutex<Vec<String>>>, refuse_connect: Arc<AtomicUsize>) {
    let head = read_head(&mut client);
    let text = String::from_utf8_lossy(&head).into_owned();
    let first = text.lines().next().unwrap_or_default().to_string();
    seen.lock().unwrap().push(text.clone());

    let mut parts = first.split(' ');
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();
    let version = parts.next().unwrap_or("HTTP/1.1");

    if method == "CONNECT" {
        if refuse_connect.load(Ordering::SeqCst) != 0 {
            reply(&mut client, "HTTP/1.1 403 Forbidden");
            return;
        }
        let origin = match TcpStream::connect(target) {
            Ok(s) => s,
            Err(_) => {
                reply(&mut client, "HTTP/1.1 502 Bad Gateway");
                return;
            }
        };
        let _ = client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n");
        let _ = client.flush();
        splice(client, origin);
        return;
    }

    let url = match courierust::courierust_http::uri::Url::parse(target) {
        Ok(u) => u,
        Err(_) => {
            reply(&mut client, "HTTP/1.1 400 Bad Request");
            return;
        }
    };
    let origin = match TcpStream::connect((url.host.as_str(), url.port)) {
        Ok(s) => s,
        Err(_) => {
            reply(&mut client, "HTTP/1.1 502 Bad Gateway");
            return;
        }
    };
    let mut rewritten = String::with_capacity(text.len());
    rewritten.push_str(method);
    rewritten.push(' ');
    rewritten.push_str(url.path_and_query.as_str());
    rewritten.push(' ');
    rewritten.push_str(version);
    for line in text[first.len()..].split("\r\n").filter(|l| !l.is_empty()) {
        if line
            .split(':')
            .next()
            .is_some_and(|name| name.eq_ignore_ascii_case("proxy-authorization"))
        {
            continue;
        }
        rewritten.push_str("\r\n");
        rewritten.push_str(line);
    }
    rewritten.push_str("\r\n\r\n");

    let mut origin = origin;
    let _ = origin.write_all(rewritten.as_bytes());
    let _ = origin.flush();
    splice(client, origin);
}

struct TestProxy {
    addr: SocketAddr,
    /// Every request head the proxy was asked to handle, in order.
    seen: Arc<Mutex<Vec<String>>>,
    refuse_connect: Arc<AtomicUsize>,
    /// Kept so the listening socket outlives the test body.
    _listener: TcpListener,
}

impl TestProxy {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test proxy");
        let addr = listener.local_addr().expect("proxy addr");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let refuse_connect = Arc::new(AtomicUsize::new(0));
        let accept = listener.try_clone().expect("clone listener");
        let seen_thread = seen.clone();
        let refuse_thread = refuse_connect.clone();
        std::thread::spawn(move || {
            for stream in accept.incoming() {
                let Ok(stream) = stream else { break };
                let seen = seen_thread.clone();
                let refuse = refuse_thread.clone();
                std::thread::spawn(move || handle(stream, seen, refuse));
            }
        });
        Self {
            addr,
            seen,
            refuse_connect,
            _listener: listener,
        }
    }

    fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn url_with_credentials(&self) -> String {
        format!("http://alice:s3cret@{}", self.addr)
    }

    fn requests(&self) -> Vec<String> {
        self.seen.lock().unwrap().clone()
    }

    fn refuse_connect(&self) {
        self.refuse_connect.store(1, Ordering::SeqCst);
    }
}

/// An HTTP origin that answers `200` with `body`, counting its hits.
fn spawn_origin(body: &'static str, hits: Arc<AtomicUsize>) -> String {
    let server = Server::bind_with_config("127.0.0.1:0", ServerConfig::default()).unwrap();
    let addr = server.local_addr().unwrap();
    let handle = server
        .serve_background(move |_req: Request<Body>| {
            hits.fetch_add(1, Ordering::SeqCst);
            let mut resp = Response::<Body>::with_status(200.into());
            resp.body = Body::Bytes(courierust::courierust_bytes::Bytes::from_static(
                body.as_bytes(),
            ));
            resp
        })
        .unwrap();
    std::mem::forget(handle);
    format!("http://{addr}")
}

fn client_through(proxy: String) -> Client {
    Client::with_config(ClientConfig {
        proxy: Some(proxy),
        ..Default::default()
    })
}

#[test]
fn an_http_request_reaches_the_proxy_in_absolute_form() {
    let hits = Arc::new(AtomicUsize::new(0));
    let origin = spawn_origin("via-origin", hits.clone());
    let proxy = TestProxy::start();

    let client = client_through(proxy.url());
    let resp = client.get(&format!("{origin}/path?q=1")).unwrap();
    assert_eq!(resp.status.as_u16(), 200);
    assert_eq!(resp.body.collect().unwrap().to_str().unwrap(), "via-origin");
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    let seen = proxy.requests();
    assert_eq!(seen.len(), 1, "exactly one request to the proxy");
    let head = &seen[0];
    let first = head.lines().next().unwrap();
    assert!(
        first.starts_with(&format!("GET {origin}/path?q=1 HTTP/1.1")),
        "a forward proxy is addressed by the absolute target, got `{first}`"
    );
    assert!(
        head.to_ascii_lowercase()
            .contains(&format!("host: {}", origin.trim_start_matches("http://"))),
        "Host must stay the origin's, so the proxy knows who it is fetching for: {head}"
    );
}

#[test]
fn an_https_request_is_tunnelled_so_the_proxy_never_sees_it() {
    let server = Server::bind_with_config(
        "127.0.0.1:0",
        ServerConfig {
            http2: false,
            threads: 1,
            tls: Some(ServerTls {
                identity: common::server_identity(),
                alpn: vec![b"http/1.1".to_vec()],
                ..Default::default()
            }),
            ..Default::default()
        },
    )
    .unwrap();
    let addr = server.local_addr().unwrap();
    let handle = server
        .serve_background(|_req: Request<Body>| {
            let mut resp = Response::<Body>::with_status(200.into());
            resp.body = Body::Bytes(courierust::courierust_bytes::Bytes::from_static(
                b"secret-payload",
            ));
            resp
        })
        .unwrap();
    std::mem::forget(handle);

    let proxy = TestProxy::start();
    let client = Client::with_config(ClientConfig {
        proxy: Some(proxy.url()),
        tls: Some(ClientTls {
            roots: common::root_store(),
            verify: true,
            alpn: vec![b"http/1.1".to_vec()],
            now: common::NOW,
            ..Default::default()
        }),
        ..Default::default()
    });

    let resp = client
        .get(&format!("https://{addr}/a-very-secret-path"))
        .unwrap();
    assert_eq!(resp.status.as_u16(), 200);
    assert_eq!(
        resp.body.collect().unwrap().to_str().unwrap(),
        "secret-payload"
    );

    let seen = proxy.requests();
    assert_eq!(seen.len(), 1, "a tunnel is one CONNECT");
    assert!(
        seen[0]
            .lines()
            .next()
            .unwrap()
            .starts_with(&format!("CONNECT {addr} HTTP/1.1")),
        "the proxy is asked for a tunnel to the origin, got `{}`",
        seen[0].lines().next().unwrap()
    );
    assert!(
        !seen[0].contains("a-very-secret-path"),
        "the tunnel exists so the proxy cannot read the request: {}",
        seen[0]
    );
}

#[test]
fn an_h2_connection_is_tunnelled_the_same_way() {
    // The h2 driver gets a `ConnStream` like the h1 connection does, so the
    // tunnel has to be built in the same place for both — this is the test
    // that fails if that wiring drifts.
    let server = Server::bind_with_config(
        "127.0.0.1:0",
        ServerConfig {
            http2: true,
            threads: 1,
            tls: Some(ServerTls {
                identity: common::server_identity(),
                alpn: vec![b"h2".to_vec()],
                ..Default::default()
            }),
            h2_settings_timeout: Some(std::time::Duration::from_secs(60)),
            h2_ping_interval: None,
            h2_ping_timeout: None,
            h2_idle_timeout: None,
            ..Default::default()
        },
    )
    .unwrap();
    let addr = server.local_addr().unwrap();
    let handle = server
        .serve_background(|_req: Request<Body>| {
            let mut resp = Response::<Body>::with_status(200.into());
            resp.body = Body::Bytes(courierust::courierust_bytes::Bytes::from_static(
                b"h2-through-a-tunnel",
            ));
            resp
        })
        .unwrap();
    std::mem::forget(handle);

    let proxy = TestProxy::start();
    let client = Client::with_config(ClientConfig {
        http2: true,
        proxy: Some(proxy.url()),
        tls: Some(ClientTls {
            roots: common::root_store(),
            verify: true,
            alpn: vec![b"h2".to_vec()],
            now: common::NOW,
            ..Default::default()
        }),
        ..Default::default()
    });

    let resp = client.get(&format!("https://{addr}/h2-path")).unwrap();
    assert_eq!(resp.status.as_u16(), 200);
    assert_eq!(
        resp.body.collect().unwrap().to_str().unwrap(),
        "h2-through-a-tunnel"
    );

    let seen = proxy.requests();
    assert_eq!(seen.len(), 1, "an h2 connection is one tunnel");
    assert!(
        seen[0]
            .lines()
            .next()
            .unwrap()
            .starts_with(&format!("CONNECT {addr} HTTP/1.1")),
        "got `{}`",
        seen[0].lines().next().unwrap()
    );
    assert!(!seen[0].contains("h2-path"));
}

#[test]
fn proxy_credentials_go_to_the_proxy_and_not_to_the_origin() {
    let seen_auth = Arc::new(Mutex::new(true));
    let seen_auth_origin = seen_auth.clone();
    let server = Server::bind_with_config("127.0.0.1:0", ServerConfig::default()).unwrap();
    let addr = server.local_addr().unwrap();
    let handle = server
        .serve_background(move |req: Request<Body>| {
            *seen_auth_origin.lock().unwrap() = req.headers.contains_key("proxy-authorization");
            Response::<Body>::with_status(200.into())
        })
        .unwrap();
    std::mem::forget(handle);

    let proxy = TestProxy::start();
    let client = client_through(proxy.url_with_credentials());
    let resp = client.get(&format!("http://{addr}/")).unwrap();
    assert_eq!(resp.status.as_u16(), 200);

    let seen = proxy.requests();
    // Header names travel lowercased, so match the name case-insensitively
    // while comparing the credential itself byte for byte.
    let authorization = seen[0]
        .lines()
        .find(|line| {
            line.split(':')
                .next()
                .is_some_and(|name| name.eq_ignore_ascii_case("proxy-authorization"))
        })
        .unwrap_or_else(|| {
            panic!(
                "the proxy must be given the credentials from the proxy URL: {}",
                seen[0]
            )
        });
    // `Basic` + base64("alice:s3cret").
    assert_eq!(
        authorization.split_once(':').expect("name: value").1.trim(),
        "Basic YWxpY2U6czNjcmV0"
    );
    assert!(
        !*seen_auth.lock().unwrap(),
        "the origin must never see Proxy-Authorization"
    );
}

#[test]
fn a_refused_connect_fails_the_request_instead_of_falling_back() {
    let proxy = TestProxy::start();
    proxy.refuse_connect();

    // An `https://` target is the one that needs a tunnel; the origin does
    // not have to exist, because the refusal comes first.
    let client = Client::with_config(ClientConfig {
        proxy: Some(proxy.url()),
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
        .get("https://127.0.0.1:9/")
        .expect_err("a refused tunnel must not be silently bypassed");
    assert!(
        err.to_string().contains("403"),
        "the error must say what the proxy answered, got: {err}"
    );
}

#[test]
fn a_proxy_url_that_cannot_be_honoured_is_an_error_not_a_bypass() {
    let hits = Arc::new(AtomicUsize::new(0));
    let origin = spawn_origin("nope", hits.clone());

    let tls_proxy = client_through("https://127.0.0.1:1".to_string());
    let err = tls_proxy.get(&format!("{origin}/")).unwrap_err();
    assert!(
        err.to_string().contains("https") && err.to_string().contains("not supported"),
        "a TLS proxy must be refused explicitly, got: {err}"
    );

    let path_proxy = client_through("http://127.0.0.1:1/pac".to_string());
    let err = path_proxy.get(&format!("{origin}/")).unwrap_err();
    assert!(
        err.to_string().contains("path"),
        "a proxy URL with a path is a misconfiguration, got: {err}"
    );

    let h2c = Client::with_config(ClientConfig {
        proxy: Some("http://127.0.0.1:1".to_string()),
        http2: true,
        ..Default::default()
    });
    let err = h2c.get(&format!("{origin}/")).unwrap_err();
    assert!(
        err.to_string().contains("h2c"),
        "clear-text HTTP/2 has no forward-proxy form here, got: {err}"
    );

    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "nothing may reach the origin when the proxy configuration is refused"
    );
}
