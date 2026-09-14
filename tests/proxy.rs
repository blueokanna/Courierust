//! Outbound proxying: `CONNECT` tunnels (RFC 9110 §9.3.6) for secure
//! targets, the absolute request form (RFC 9112 §3.2.2) for plaintext
//! ones.
//!
//! The proxy in these tests is written with the standard library only and
//! knows nothing about the client: it speaks the standards and records
//! the request lines it was asked to serve. That record is the evidence.
//! A client that quietly skipped the proxy — or one that sent its
//! `Proxy-Authorization` on past the tunnel to the origin — would still
//! return `200`, so the assertions are about what each hop actually saw.

mod common;

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

use courierust::courierust_body::Body;
use courierust::courierust_client::{Client, ClientConfig, Proxy, TlsSettings as ClientTls};
use courierust::courierust_http::header::{HeaderName, HeaderValue};
use courierust::courierust_http::method::Method;
use courierust::courierust_http::request::Request;
use courierust::courierust_http::response::Response;
use courierust::courierust_http::uri::PathAndQuery;
use courierust::courierust_server::{Server, ServerConfig, TlsSettings as ServerTls};

/// What a hop was asked to do, in order.
#[derive(Clone, Default)]
struct Seen(Arc<Mutex<Vec<String>>>);

impl Seen {
    fn record(&self, line: &str) {
        self.0.lock().unwrap().push(line.to_string());
    }

    fn lines(&self) -> Vec<String> {
        self.0.lock().unwrap().clone()
    }
}

/// How the test proxy answers.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Reply {
    Serve,
    Refuse,
}

fn spawn_proxy(seen: Seen, reply: Reply) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let seen = seen.clone();
            std::thread::spawn(move || serve_proxy_connection(stream, &seen, reply));
        }
    });
    addr
}

/// Serve one proxied connection: a `CONNECT` is answered and then relayed
/// byte for byte, any other request is forwarded to the origin named by
/// its absolute-form target after rewriting that target to the origin-form
/// a server expects.
fn serve_proxy_connection(mut down: TcpStream, seen: &Seen, reply: Reply) {
    let Some(head) = read_head(&mut down) else {
        return;
    };
    let text = String::from_utf8_lossy(&head).to_string();
    let request_line = text.lines().next().unwrap_or_default().to_string();
    seen.record(&request_line);
    // One line per credential field, value included: a handshake that
    // carries two `Proxy-Authorization` fields — a configured one and the
    // request's own — is exactly the bug this records, and only the value
    // shows which of them survived.
    for line in text.lines().skip(1) {
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("proxy-authorization") {
                seen.record(&format!("proxy-authorization: {}", value.trim()));
            }
        }
    }
    if reply == Reply::Refuse {
        let _ = down.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n");
        return;
    }

    let target = request_line
        .split(' ')
        .nth(1)
        .unwrap_or_default()
        .to_string();
    let tunnel = request_line.starts_with("CONNECT ");
    let dial = if tunnel {
        target.clone()
    } else {
        authority_form(&target).to_string()
    };
    let Ok(mut up) = TcpStream::connect(dial) else {
        let _ = down.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n");
        return;
    };

    if tunnel {
        if down
            .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
            .is_err()
        {
            return;
        }
    } else {
        let rewritten = text.replacen(&target, origin_form(&target), 1);
        if up.write_all(rewritten.as_bytes()).is_err() {
            return;
        }
    }
    relay(down, up);
}

/// The authority (`host:port`) of an absolute request target.
fn authority_form(target: &str) -> &str {
    let rest = target
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(target);
    rest.split('/').next().unwrap_or_default()
}

/// The origin-form target (`/path?query`) of an absolute request target.
fn origin_form(target: &str) -> &str {
    let rest = target
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(target);
    match rest.find('/') {
        Some(at) => &rest[at..],
        None => "/",
    }
}

/// Read exactly one request head: the first byte after it belongs to one
/// of the two peers, so nothing past the terminator may be consumed.
fn read_head(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match stream.read(&mut byte) {
            Ok(1) => head.push(byte[0]),
            _ => return None,
        }
        if head.ends_with(b"\r\n\r\n") {
            return Some(head);
        }
        if head.len() > 16 * 1024 {
            return None;
        }
    }
}

/// Relay both directions until either side stops.
fn relay(down: TcpStream, up: TcpStream) {
    let down_read = down.try_clone().expect("clone the client side");
    let up_read = up.try_clone().expect("clone the origin side");
    let upload = std::thread::spawn(move || {
        let (mut from, mut to) = (down_read, up);
        let _ = std::io::copy(&mut from, &mut to);
        let _ = to.shutdown(Shutdown::Write);
    });
    let (mut from, mut to) = (up_read, down);
    let _ = std::io::copy(&mut from, &mut to);
    let _ = to.shutdown(Shutdown::Write);
    let _ = upload.join();
}

/// An origin that echoes the request and records whether a
/// `Proxy-Authorization` field reached it.
fn spawn_origin(config: ServerConfig, seen: Seen, secure: bool) -> String {
    let handler = move |req: Request<Body>| -> Response<Body> {
        seen.record(if req.headers.contains_key("proxy-authorization") {
            "proxy-authorization"
        } else {
            "no proxy-authorization"
        });
        let mut resp = Response::<Body>::with_status(200.into());
        resp.headers.insert(
            HeaderName::from_lowercase("x-method"),
            HeaderValue::from_bytes(req.method.as_str().as_bytes()).unwrap(),
        );
        resp
    };
    let server = Server::bind_with_config("127.0.0.1:0", config).unwrap();
    let addr = server.local_addr().unwrap();
    let handle = server.serve_background(handler).unwrap();
    std::mem::forget(handle);
    format!("{}://{addr}", if secure { "https" } else { "http" })
}

fn https_origin_config() -> ServerConfig {
    ServerConfig {
        threads: 1,
        tls: Some(ServerTls {
            identity: common::server_identity(),
            alpn: vec![b"http/1.1".to_vec()],
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn tls_client_settings() -> ClientTls {
    ClientTls {
        roots: common::root_store(),
        verify: true,
        alpn: vec![b"http/1.1".to_vec()],
        now: common::NOW,
        ..Default::default()
    }
}

/// An `https://` request reaches the origin through the proxy's tunnel,
/// and the credentials belong to the proxy: the origin never sees them.
#[test]
fn https_requests_go_through_a_connect_tunnel() {
    let proxy_seen = Seen::default();
    let origin_seen = Seen::default();
    let proxy = spawn_proxy(proxy_seen.clone(), Reply::Serve);
    let origin = spawn_origin(https_origin_config(), origin_seen.clone(), true);

    let client = Client::with_config(ClientConfig {
        tls: Some(tls_client_settings()),
        proxy: Some(
            Proxy::new(&format!("http://{proxy}"))
                .unwrap()
                .basic("alice", "s3cret"),
        ),
        ..Default::default()
    });
    let resp = client.get(&format!("{origin}/tunnelled")).unwrap();
    assert_eq!(resp.status.as_u16(), 200);
    assert_eq!(
        resp.headers.get("x-method").unwrap().to_str().unwrap(),
        "GET"
    );

    let authority = origin.trim_start_matches("https://").to_string();
    assert_eq!(
        proxy_seen.lines(),
        vec![
            format!("CONNECT {authority} HTTP/1.1"),
            format!(
                "proxy-authorization: Basic {}",
                courierust::courierust_crypto::base64::encode(b"alice:s3cret")
            ),
        ],
        "the client must ask the proxy for a tunnel, with its credentials"
    );
    assert_eq!(
        origin_seen.lines(),
        vec!["no proxy-authorization".to_string()],
        "proxy credentials must not travel past the proxy"
    );
}

/// A plaintext request through a proxy uses the absolute request form,
/// which is what tells the proxy where the request is going.
#[test]
fn plaintext_requests_use_the_absolute_form() {
    let proxy_seen = Seen::default();
    let origin_seen = Seen::default();
    let proxy = spawn_proxy(proxy_seen.clone(), Reply::Serve);
    let origin = spawn_origin(
        ServerConfig {
            threads: 1,
            ..Default::default()
        },
        origin_seen.clone(),
        false,
    );

    let client = Client::with_config(ClientConfig {
        proxy: Some(Proxy::new(&proxy.to_string()).unwrap()),
        ..Default::default()
    });
    let resp = client.get(&format!("{origin}/plain")).unwrap();
    assert_eq!(resp.status.as_u16(), 200);
    assert_eq!(
        proxy_seen.lines(),
        vec![format!("GET {origin}/plain HTTP/1.1")],
        "the request line must name the origin in absolute form"
    );
}

/// A refused `CONNECT` fails the request with the proxy's status instead
/// of a tunnel that is not there.
#[test]
fn a_refused_connect_surfaces_the_proxy_status() {
    let proxy_seen = Seen::default();
    let proxy = spawn_proxy(proxy_seen.clone(), Reply::Refuse);
    let client = Client::with_config(ClientConfig {
        tls: Some(tls_client_settings()),
        proxy: Some(Proxy::new(&proxy.to_string()).unwrap()),
        ..Default::default()
    });
    let err = client
        .get("https://127.0.0.1:9/never")
        .expect_err("a refused tunnel must fail the request");
    let text = err.to_string();
    assert!(text.contains("403"), "{text}");
    assert!(text.contains("CONNECT"), "{text}");
    assert_eq!(proxy_seen.lines().len(), 1);
}

/// A `Proxy-Authorization` the request carries itself wins over the
/// client's configured default, and the proxy must never be handed two of
/// them to choose from.
#[test]
fn a_request_provided_proxy_credential_wins() {
    let proxy_seen = Seen::default();
    let proxy = spawn_proxy(proxy_seen.clone(), Reply::Serve);
    let origin = spawn_origin(
        ServerConfig {
            threads: 1,
            ..Default::default()
        },
        Seen::default(),
        false,
    );

    let client = Client::with_config(ClientConfig {
        proxy: Some(
            Proxy::new(&proxy.to_string())
                .unwrap()
                .basic("alice", "s3cret"),
        ),
        ..Default::default()
    });
    let req = Request::new(Method::GET, "/own").header("proxy-authorization", "Bearer per-request");
    let resp = client.execute(&origin, req).unwrap();
    assert_eq!(resp.status.as_u16(), 200);

    // A second client — so a second connection, since this proxy relays the
    // rest of a connection it has already routed — shows the *configured*
    // credential going out when the request carries none.
    let configured = Client::with_config(ClientConfig {
        proxy: Some(
            Proxy::new(&proxy.to_string())
                .unwrap()
                .basic("alice", "s3cret"),
        ),
        ..Default::default()
    });
    let resp = configured.get(&format!("{origin}/configured")).unwrap();
    assert_eq!(resp.status.as_u16(), 200);

    assert_eq!(
        proxy_seen.lines(),
        vec![
            format!("GET {origin}/own HTTP/1.1"),
            "proxy-authorization: Bearer per-request".to_string(),
            format!("GET {origin}/configured HTTP/1.1"),
            format!(
                "proxy-authorization: Basic {}",
                courierust::courierust_crypto::base64::encode(b"alice:s3cret")
            ),
        ],
        "the request's own field wins, the configured one is sent when it is absent, and \
         neither hop ever sees two"
    );
}

/// `OPTIONS *` names the server itself. Through a proxy it travels as the
/// absolute form with an empty path (RFC 9110 §9.3.7); the last proxy
/// turns it back into `*` before the origin sees it.
#[test]
fn an_asterisk_target_becomes_an_empty_path_through_a_proxy() {
    let proxy_seen = Seen::default();
    let proxy = spawn_proxy(proxy_seen.clone(), Reply::Serve);
    let origin = spawn_origin(
        ServerConfig {
            threads: 1,
            ..Default::default()
        },
        Seen::default(),
        false,
    );

    let client = Client::with_config(ClientConfig {
        proxy: Some(Proxy::new(&proxy.to_string()).unwrap()),
        ..Default::default()
    });
    let resp = client
        .execute(
            &origin,
            Request::new(Method::OPTIONS, PathAndQuery::from_static("*")),
        )
        .unwrap();
    assert_eq!(resp.status.as_u16(), 200);
    assert_eq!(
        proxy_seen.lines(),
        vec![format!("OPTIONS {origin} HTTP/1.1")],
        "the asterisk target must become the origin with an empty path"
    );
}

/// The two protocol/proxy combinations that cannot work are refused
/// rather than half-served: QUIC is UDP while the tunnel is TCP, and a
/// proxy routes plaintext by reading HTTP/1.1, which is not what h2c
/// frames are.
#[test]
fn proxy_incompatible_protocols_are_refused() {
    let client = Client::with_config(ClientConfig {
        http3: true,
        tls: Some(tls_client_settings()),
        proxy: Some(Proxy::new("http://127.0.0.1:8080").unwrap()),
        ..Default::default()
    });
    let err = client
        .get("https://127.0.0.1:9/never")
        .expect_err("http3 + proxy must be refused");
    assert!(err.to_string().contains("proxy"), "{err}");

    let client = Client::with_config(ClientConfig {
        http2: true,
        proxy: Some(Proxy::new("http://127.0.0.1:8080").unwrap()),
        ..Default::default()
    });
    let err = client
        .get("http://127.0.0.1:9/never")
        .expect_err("h2c + proxy must be refused");
    assert!(err.to_string().contains("h2c"), "{err}");
}
