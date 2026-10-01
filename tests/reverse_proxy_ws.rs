//! WebSocket upgrades through the reverse proxy, end to end: a real
//! upstream WebSocket server, a real proxy, a real client.
//!
//! The upstream answers with a marker (`upstream:`) so a passing assertion
//! cannot be the proxy echoing to itself — which is exactly what a broken
//! bridge would do.

use courierust::courierust_body::Body;
use courierust::courierust_client::ws::{WebSocket, WsClientOptions};
use courierust::courierust_client::{Client, ClientConfig};
use courierust::courierust_http::request::Request;
use courierust::courierust_http::response::Response;
use courierust::courierust_http::uri::Url;
use courierust::courierust_server::reverse_proxy::{Matcher, ReverseProxy, Route};
use courierust::courierust_server::ws::{WsConn, WsData, WsService, WsUpgradeReply};
use courierust::courierust_server::{Handler, Server, ServerConfig};
use courierust::courierust_ws::Event;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

/// An upstream that answers every message with a marker.
struct Echo;

impl WsService for Echo {
    fn on_message(&self, c: &mut WsConn, msg: WsData) {
        match msg {
            WsData::Text(text) => {
                let _ = c.send_text(&format!("upstream:{text}"));
            }
            WsData::Binary(bytes) => {
                let _ = c.send_binary(bytes.as_slice());
            }
        }
    }
}

/// The upstream's HTTP face: no plain routes, every upgrade accepted.
struct Upstream;

impl Handler for Upstream {
    fn handle(&self, _req: Request<Body>) -> Response<Body> {
        Response::<Body>::with_status(404.into())
    }

    fn websocket(&self, _req: &Request<Body>) -> WsUpgradeReply {
        WsUpgradeReply::Accept(Arc::new(Echo))
    }
}

/// An upstream WebSocket server that negotiates `subprotocols`.
fn spawn_ws_upstream(subprotocols: Vec<String>) -> String {
    let mut config = ServerConfig::default();
    config.websocket.subprotocols = subprotocols;
    let server = Server::bind_with_config("127.0.0.1:0", config).unwrap();
    let addr = server.local_addr().unwrap();
    let handle = server.serve_background(Upstream).unwrap();
    std::mem::forget(handle);
    format!("http://{addr}")
}

/// A proxy in front of `upstream`; `upgrade` decides whether the route
/// forwards upgrades.
fn spawn_ws_proxy(upstream: &str, upgrade: bool) -> String {
    let server = Server::bind_with_config("127.0.0.1:0", ServerConfig::default()).unwrap();
    let addr = server.local_addr().unwrap();
    let route = Route::to(
        Matcher::Prefix("/".to_string()),
        Url::parse(upstream).unwrap(),
    )
    .upgrade(upgrade);
    let handle = server
        .serve_background(ReverseProxy::new(Client::new()).add_route(route))
        .unwrap();
    std::mem::forget(handle);
    format!("http://{addr}")
}

/// The `ws://` URL for `path` on a proxy whose base is an `http://` URL.
fn ws_url(proxy: &str, path: &str) -> String {
    format!(
        "ws://{}{path}",
        proxy.strip_prefix("http://").expect("an http base")
    )
}

#[test]
fn messages_cross_both_legs_of_the_proxy() {
    let upstream = spawn_ws_upstream(Vec::new());
    let proxy = spawn_ws_proxy(&upstream, true);
    let mut ws = WebSocket::connect(&ws_url(&proxy, "/chat"), &ClientConfig::default()).unwrap();

    ws.send_text("hello").unwrap();
    assert_eq!(
        ws.read_message().unwrap(),
        Event::Text("upstream:hello".to_string())
    );

    ws.send_binary(&[0x00, 0xff, 0x10]).unwrap();
    match ws.read_message().unwrap() {
        Event::Binary(bytes) => assert_eq!(bytes.as_slice(), &[0x00, 0xff, 0x10]),
        other => panic!("expected the upstream's binary answer, got {other:?}"),
    }

    ws.close(1000, "bye").unwrap();
}

#[test]
fn the_subprotocol_the_upstream_picks_is_the_one_the_client_is_told() {
    // The proxy's own server knows nothing about `chat`, so a `101` naming it
    // can only be the upstream's decision being passed on.
    let upstream = spawn_ws_upstream(vec!["chat".to_string()]);
    let proxy = spawn_ws_proxy(&upstream, true);
    let options = WsClientOptions {
        protocols: vec!["chat".to_string()],
        ..Default::default()
    };
    let mut ws =
        WebSocket::connect_with(&ws_url(&proxy, "/chat"), &ClientConfig::default(), &options)
            .unwrap();

    assert_eq!(ws.protocol(), Some("chat"));
    ws.send_text("hi").unwrap();
    assert_eq!(
        ws.read_message().unwrap(),
        Event::Text("upstream:hi".to_string())
    );
}

#[test]
fn a_route_that_did_not_opt_in_answers_501() {
    let upstream = spawn_ws_upstream(Vec::new());
    let proxy = spawn_ws_proxy(&upstream, false);

    let status = upgrade_status(&proxy);
    assert!(
        status.starts_with("HTTP/1.1 501"),
        "an upgrade nobody forwards is refused, not half-accepted: {status}"
    );
}

/// Send a hand-written upgrade request and return the response head.
///
/// This crate's own client strips `Connection`/`Upgrade` — they are
/// hop-by-hop, and it has no upgrade support — so being the peer is the only
/// way to put one on the wire.
fn upgrade_status(proxy: &str) -> String {
    let authority = proxy.trim_start_matches("http://");
    let mut socket = TcpStream::connect(authority).expect("connect to the proxy");
    socket
        .write_all(
            format!(
                "GET /chat HTTP/1.1\r\nHost: {authority}\r\nConnection: Upgrade\r\n\
                 Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\n\
                 Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
            )
            .as_bytes(),
        )
        .expect("write the upgrade request");
    socket.flush().unwrap();
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") && head.len() < 512 {
        if socket.read(&mut byte).unwrap_or(0) == 0 {
            break;
        }
        head.push(byte[0]);
    }
    String::from_utf8_lossy(&head).into_owned()
}
