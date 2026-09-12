//! A WebSocket echo server plus a client that exercises it, in one
//! process: upgrade, a text round trip, a binary round trip, a
//! server-initiated push to the same connection, the negotiated
//! subprotocol, and a clean close handshake.
//!
//! Run with:
//! ```text
//! cargo run --example ws_echo
//! ```

use courierust::courierust_body::Body;
use courierust::courierust_client::ws::{WebSocket, WsClientOptions};
use courierust::courierust_client::ClientConfig;
use courierust::courierust_http::request::Request;
use courierust::courierust_http::response::Response;
use courierust::courierust_server::ws::{WsConn, WsData, WsService, WsUpgradeReply};
use courierust::courierust_server::{Handler, Server, ServerConfig};
use std::sync::Arc;

/// Echoes messages, answers a `!greet` command with a push, and honours
/// the subprotocol the client asked for.
struct Echo;

impl WsService for Echo {
    fn on_open(&self, conn: &mut WsConn) {
        let info = conn.info();
        println!(
            "open: path={} peer={} secure={} protocol={:?} compression={:?}",
            info.path,
            info.client_ip,
            info.secure,
            info.protocol,
            info.compression
        );
    }

    fn on_message(&self, conn: &mut WsConn, msg: WsData) {
        match msg {
            WsData::Text(text) => {
                if text == "!greet" {
                    // A server-initiated message on the same connection.
                    let _ = conn.send_text("hello from the server");
                    return;
                }
                let _ = conn.send_text(&text);
            }
            WsData::Binary(bytes) => {
                let _ = conn.send_binary(&bytes);
            }
        }
    }

    fn on_pong(&self, conn: &mut WsConn, payload: &[u8]) {
        println!("pong from {}: {payload:?}", conn.info().client_ip);
    }

    fn on_close(&self, _conn: &mut WsConn, code: Option<u16>, clean: bool) {
        println!("close: code={code:?} clean={clean}");
    }
}

/// Routes `/ws` to the WebSocket service and everything else to HTTP.
struct App;

impl Handler for App {
    fn handle(&self, _req: Request<Body>) -> Response<Body> {
        let mut resp = Response::with_status(
            courierust::courierust_http::status::StatusCode::from_u16(200),
        );
        resp.body = Body::Bytes(
            b"this route is plain HTTP; connect to /ws instead"
                .as_slice()
                .into(),
        );
        resp
    }

    fn websocket(&self, req: &Request<Body>) -> WsUpgradeReply {
        if req.uri.path() == "/ws" {
            WsUpgradeReply::Accept(Arc::new(Echo))
        } else {
            // Let the HTTP handler answer: a 404 rather than a refused
            // upgrade, which is what a client expects from a wrong path.
            WsUpgradeReply::Pass
        }
    }
}

fn main() -> courierust::Result<()> {
    let server = Server::bind_with_config(
        "127.0.0.1:0",
        ServerConfig {
            websocket: courierust::courierust_server::ws::WsConfig {
                // The default is SameOrigin, which a non-browser client
                // does not satisfy unless it sends an Origin header. This
                // example talks to itself over loopback, so any origin is
                // fine *here* — a real deployment wants SameOrigin or a
                // List.
                origin: courierust::courierust_ws::OriginPolicy::Any,
                subprotocols: vec!["courierust.echo".into()],
                ..Default::default()
            },
            ..Default::default()
        },
    )?;
    let addr = server.local_addr()?;
    let _handle = server.serve_background(App)?;
    println!("listening on {addr}");

    let opts = WsClientOptions {
        protocols: vec!["courierust.echo".into()],
        ..Default::default()
    };
    let mut ws = WebSocket::connect_with(
        &format!("ws://{addr}/ws"),
        &ClientConfig::default(),
        &opts,
    )?;
    println!("connected: protocol={:?}", ws.protocol());

    ws.send_text("hello over a WebSocket")?;
    println!("echo   -> {:?}", ws.read_message()?);

    ws.send_binary(b"\x00\x01\x02\x03")?;
    println!("binary -> {:?}", ws.read_message()?);

    ws.send_text("!greet")?;
    println!("push   -> {:?}", ws.read_message()?);

    // Ping/Pong is answered by the session automatically; this checks the
    // answer comes back without the application doing anything.
    ws.send_ping(b"keepalive")?;
    println!("pong   -> {:?}", ws.read_message()?);

    println!("stats  -> {:?}", ws.stats());
    ws.close(1000, "bye")?;
    println!("closed cleanly: is_closed={}", ws.is_closed());
    Ok(())
}
