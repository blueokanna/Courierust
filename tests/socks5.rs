//! SOCKS5 and `no_proxy` behaviour.
//!
//! Like `tests/proxy.rs`, the proxy here is the simplest thing that deserves
//! the name: it records what it was asked for and then moves bytes. What is
//! under test is the client's conformance to RFC 1928, not the proxy.

mod common;

use courierust::courierust_body::Body;
use courierust::courierust_client::{Client, ClientConfig, TlsSettings as ClientTls};
use courierust::courierust_http::request::Request;
use courierust::courierust_http::response::Response;
use courierust::courierust_server::{Server, ServerConfig, TlsSettings as ServerTls};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

/// Pipe both directions until one side goes away.
fn splice(a: TcpStream, b: TcpStream) {
    let (mut a_read, mut b_write) = (a.try_clone().expect("clone"), b.try_clone().expect("clone"));
    std::thread::spawn(move || {
        let _ = std::io::copy(&mut a_read, &mut b_write);
    });
    let mut b_read = b;
    let mut a_write = a;
    let _ = std::io::copy(&mut b_read, &mut a_write);
}

fn read_byte(stream: &mut TcpStream) -> Option<u8> {
    let mut one = [0u8; 1];
    stream.read_exact(&mut one).ok().map(|_| one[0])
}

/// A SOCKS5 server (RFC 1928) with optional RFC 1929 authentication.
struct Socks5Proxy {
    addr: SocketAddr,
    /// What each `CONNECT` asked for, e.g. `domain(example.com):443`.
    seen: Arc<Mutex<Vec<String>>>,
    /// Filled with the credentials the client actually sent.
    got: Arc<Mutex<Option<(String, String)>>>,
    _listener: TcpListener,
}

impl Socks5Proxy {
    fn start(require: Option<(&str, &str)>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind socks proxy");
        let addr = listener.local_addr().expect("socks addr");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let require = Arc::new(Mutex::new(
            require.map(|(u, p)| (u.to_string(), p.to_string())),
        ));
        let got = Arc::new(Mutex::new(None));
        let accept = listener.try_clone().expect("clone listener");
        let (seen_thread, require_thread, got_thread) =
            (seen.clone(), require.clone(), got.clone());
        std::thread::spawn(move || {
            for stream in accept.incoming() {
                let Ok(stream) = stream else { break };
                let (seen, require, got) = (
                    seen_thread.clone(),
                    require_thread.clone(),
                    got_thread.clone(),
                );
                std::thread::spawn(move || handle_socks5(stream, seen, require, got));
            }
        });
        Self {
            addr,
            seen,
            got,
            _listener: listener,
        }
    }

    fn url(&self, scheme: &str) -> String {
        format!("{scheme}://{}", self.addr)
    }

    fn url_with_credentials(&self, scheme: &str) -> String {
        format!("{scheme}://alice:s3cret@{}", self.addr)
    }

    fn seen(&self) -> Vec<String> {
        self.seen.lock().unwrap().clone()
    }

    fn got(&self) -> Option<(String, String)> {
        self.got.lock().unwrap().clone()
    }
}

fn handle_socks5(
    mut client: TcpStream,
    seen: Arc<Mutex<Vec<String>>>,
    require: Arc<Mutex<Option<(String, String)>>>,
    got: Arc<Mutex<Option<(String, String)>>>,
) {
    // Greeting: version, then one method per byte.
    let Some(version) = read_byte(&mut client) else {
        return;
    };
    if version != 5 {
        return;
    }
    let Some(count) = read_byte(&mut client) else {
        return;
    };
    let mut methods = vec![0u8; usize::from(count)];
    if client.read_exact(&mut methods).is_err() {
        return;
    }
    let required = require.lock().unwrap().clone();
    let chosen = match &required {
        Some(_) if methods.contains(&2) => 2,
        None if methods.contains(&0) => 0,
        _ => 0xff,
    };
    if client.write_all(&[5, chosen]).is_err() || client.flush().is_err() {
        return;
    }
    if chosen == 0xff {
        return;
    }
    if chosen == 2 {
        // RFC 1929: version, user length + user, password length + password.
        let Some(_auth_version) = read_byte(&mut client) else {
            return;
        };
        let Some(user_len) = read_byte(&mut client) else {
            return;
        };
        let mut user = vec![0u8; usize::from(user_len)];
        if client.read_exact(&mut user).is_err() {
            return;
        }
        let Some(pass_len) = read_byte(&mut client) else {
            return;
        };
        let mut pass = vec![0u8; usize::from(pass_len)];
        if client.read_exact(&mut pass).is_err() {
            return;
        }
        let user = String::from_utf8_lossy(&user).into_owned();
        let pass = String::from_utf8_lossy(&pass).into_owned();
        *got.lock().unwrap() = Some((user.clone(), pass.clone()));
        let ok = required
            .as_ref()
            .is_some_and(|(u, p)| *u == user && *p == pass);
        let _ = client.write_all(&[1, u8::from(!ok)]);
        let _ = client.flush();
        if !ok {
            return;
        }
    }
    // Request: version, CONNECT, reserved, address type.
    let mut request = [0u8; 4];
    if client.read_exact(&mut request).is_err() {
        return;
    }
    let target = match request[3] {
        1 => {
            let mut octets = [0u8; 4];
            if client.read_exact(&mut octets).is_err() {
                return;
            }
            format!(
                "ipv4({}.{}.{}.{})",
                octets[0], octets[1], octets[2], octets[3]
            )
        }
        3 => {
            let Some(len) = read_byte(&mut client) else {
                return;
            };
            let mut name = vec![0u8; usize::from(len)];
            if client.read_exact(&mut name).is_err() {
                return;
            }
            format!("domain({})", String::from_utf8_lossy(&name))
        }
        _ => return,
    };
    let mut port_bytes = [0u8; 2];
    if client.read_exact(&mut port_bytes).is_err() {
        return;
    }
    let port = u16::from_be_bytes(port_bytes);
    seen.lock().unwrap().push(format!("{target}:{port}"));

    // Everything the test asks for is on loopback, so the proxy can just
    // dial it: the recorded label is what the assertion is about.
    let host = target
        .trim_start_matches("ipv4(")
        .trim_start_matches("domain(")
        .trim_end_matches(')');
    let origin = match TcpStream::connect((host, port)) {
        Ok(stream) => stream,
        Err(_) => {
            // Reply code 5: connection refused.
            let _ = client.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]);
            let _ = client.flush();
            return;
        }
    };
    let _ = client.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    let _ = client.flush();
    splice(client, origin);
}

/// An HTTP origin that answers `200` with `body`.
fn spawn_origin(body: &'static str) -> String {
    let server = Server::bind_with_config("127.0.0.1:0", ServerConfig::default()).unwrap();
    let addr = server.local_addr().unwrap();
    let handle = server
        .serve_background(move |_req: Request<Body>| {
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

/// An HTTPS origin, for the case where the tunnel has to carry TLS.
fn spawn_tls_origin(body: &'static str) -> String {
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
        .serve_background(move |_req: Request<Body>| {
            let mut resp = Response::<Body>::with_status(200.into());
            resp.body = Body::Bytes(courierust::courierust_bytes::Bytes::from_static(
                body.as_bytes(),
            ));
            resp
        })
        .unwrap();
    std::mem::forget(handle);
    format!("https://{addr}")
}

fn tls_settings() -> ClientTls {
    ClientTls {
        roots: common::root_store(),
        verify: true,
        alpn: vec![b"http/1.1".to_vec()],
        now: common::NOW,
        ..Default::default()
    }
}

#[test]
fn a_socks5h_proxy_is_given_the_name_and_resolves_it() {
    let origin = spawn_origin("through-socks");
    let proxy = Socks5Proxy::start(None);
    let client = Client::with_config(ClientConfig {
        proxy: Some(proxy.url("socks5h")),
        ..Default::default()
    });

    let resp = client.get(&format!("{origin}/x")).unwrap();
    assert_eq!(
        resp.body.collect().unwrap().to_str().unwrap(),
        "through-socks"
    );

    let seen = proxy.seen();
    assert_eq!(seen.len(), 1);
    let authority = origin.trim_start_matches("http://");
    let (host, port) = authority.split_once(':').unwrap();
    assert_eq!(
        seen[0],
        format!("domain({host}):{port}"),
        "socks5h sends the host name so the proxy does the resolving"
    );
}

#[test]
fn a_socks5_proxy_is_given_an_address_resolved_here() {
    let origin = spawn_origin("through-socks");
    let proxy = Socks5Proxy::start(None);
    let client = Client::with_config(ClientConfig {
        proxy: Some(proxy.url("socks5")),
        ..Default::default()
    });

    let resp = client.get(&format!("{origin}/x")).unwrap();
    assert_eq!(
        resp.body.collect().unwrap().to_str().unwrap(),
        "through-socks"
    );

    let seen = proxy.seen();
    assert_eq!(seen.len(), 1);
    let authority = origin.trim_start_matches("http://");
    let (host, port) = authority.split_once(':').unwrap();
    assert_eq!(
        seen[0],
        format!("ipv4({host}):{port}"),
        "socks5 resolves locally and sends the address"
    );
}

#[test]
fn a_socks5_tunnel_carries_tls_end_to_end() {
    let origin = spawn_tls_origin("tls-through-socks");
    let proxy = Socks5Proxy::start(None);
    let client = Client::with_config(ClientConfig {
        proxy: Some(proxy.url("socks5h")),
        tls: Some(tls_settings()),
        ..Default::default()
    });

    let resp = client.get(&format!("{origin}/secret")).unwrap();
    assert_eq!(
        resp.body.collect().unwrap().to_str().unwrap(),
        "tls-through-socks"
    );
    let seen = proxy.seen();
    assert_eq!(seen.len(), 1, "one tunnel, not one per request");
    assert!(
        !seen[0].contains("secret"),
        "the proxy saw `{}`, which is a request, not a tunnel",
        seen[0]
    );
}

#[test]
fn socks5_credentials_are_negotiated_and_a_wrong_one_is_refused() {
    let origin = spawn_origin("authed");
    let proxy = Socks5Proxy::start(Some(("alice", "s3cret")));
    let client = Client::with_config(ClientConfig {
        proxy: Some(proxy.url_with_credentials("socks5h")),
        ..Default::default()
    });
    let resp = client.get(&format!("{origin}/x")).unwrap();
    assert_eq!(resp.body.collect().unwrap().to_str().unwrap(), "authed");
    assert_eq!(
        proxy.got(),
        Some(("alice".to_string(), "s3cret".to_string())),
        "the credentials came from the proxy URL"
    );

    // The same proxy, with no credentials in the URL: the sub-negotiation
    // fails and the request must fail with it, not fall back to direct.
    let bare = Client::with_config(ClientConfig {
        proxy: Some(proxy.url("socks5h")),
        ..Default::default()
    });
    let error = bare.get(&format!("{origin}/x")).expect_err("must fail");
    assert!(
        error.to_string().contains("method"),
        "expected a method-negotiation failure, got: {error}"
    );
}

#[test]
fn no_proxy_exempts_the_host_and_leaves_the_proxy_alone() {
    let origin = spawn_origin("direct");
    let proxy = Socks5Proxy::start(None);
    let authority = origin.trim_start_matches("http://");
    let (host, port) = authority.split_once(':').unwrap();

    // Exempt by bare name, by `.name`, and with the port pinned — the three
    // spellings that appear in real `NO_PROXY` values.
    for entry in [
        host.to_string(),
        format!(".{host}"),
        format!("{host}:{port}"),
    ] {
        let client = Client::with_config(ClientConfig {
            proxy: Some(proxy.url("socks5h")),
            no_proxy: vec![entry.clone()],
            ..Default::default()
        });
        let resp = client.get(&format!("{origin}/x")).unwrap();
        assert_eq!(resp.body.collect().unwrap().to_str().unwrap(), "direct");
        assert!(
            proxy.seen().is_empty(),
            "`{entry}` must exempt the host, so the proxy is never used"
        );
    }

    // A port-pinned entry that does not match keeps the proxy in play.
    let client = Client::with_config(ClientConfig {
        proxy: Some(proxy.url("socks5h")),
        no_proxy: vec![format!("{host}:1")],
        ..Default::default()
    });
    let resp = client.get(&format!("{origin}/x")).unwrap();
    assert_eq!(resp.body.collect().unwrap().to_str().unwrap(), "direct");
    assert_eq!(proxy.seen().len(), 1, "the wrong port must not exempt");
}

#[test]
fn an_entry_that_does_not_match_keeps_the_proxy_in_use() {
    let origin = spawn_origin("still-proxied");
    let proxy = Socks5Proxy::start(None);
    let client = Client::with_config(ClientConfig {
        proxy: Some(proxy.url("socks5h")),
        no_proxy: vec!["example.com".to_string(), "other.test".to_string()],
        ..Default::default()
    });
    let resp = client.get(&format!("{origin}/x")).unwrap();
    assert_eq!(
        resp.body.collect().unwrap().to_str().unwrap(),
        "still-proxied"
    );
    assert_eq!(proxy.seen().len(), 1, "an unrelated entry must not exempt");
}
