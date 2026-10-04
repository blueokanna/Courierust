//! A fixed-port WebSocket echo server for the Autobahn test suite.
//!
//! Autobahn's fuzzing client dials a *fixed* endpoint, which the `ws_echo`
//! demo cannot provide (it binds an ephemeral port and then drives itself
//! in the same process). This binary exists for exactly one reason, and is
//! written for that reason rather than tidied into a general-purpose
//! server:
//!
//! * every path is an echo endpoint, because the suite is pointed at one
//!   URL and a `404` would be reported as a protocol failure;
//! * `permessage-deflate` is negotiated, so the suite's compression cases
//!   (`12.*`, `13.*`) actually run instead of being skipped;
//! * the `Origin` policy is `Any`, because the suite dials a loopback
//!   address while sending its own synthetic `Origin` — a same-origin
//!   check would refuse every case. That is a property of this local
//!   harness, **not** a recommendation: the default is `SameOrigin`.
//!
//! ```text
//! cargo run --release --example ws_autobahn
//! ```
//!
//! Then, in another shell:
//!
//! ```text
//! .\scripts\autobahn_ws.ps1
//! ```
//!
//! The bind address defaults to Autobahn's conventional
//! `0.0.0.0:9001` and can be overridden with `WS_AUTOBAHN_ADDR`.

use courierust::courierust_body::Body;
use courierust::courierust_http::request::Request;
use courierust::courierust_http::response::Response;
use courierust::courierust_http::status::StatusCode;
use courierust::courierust_server::ws::{WsConfig, WsConn, WsData, WsService, WsUpgradeReply};
use courierust::courierust_server::{Handler, Server, ServerConfig};
use courierust::courierust_ws::OriginPolicy;
use std::sync::Arc;

/// Echoes every message back unchanged, which is what the suite expects.
struct Echo;

impl WsService for Echo {
    fn on_message(&self, conn: &mut WsConn, msg: WsData) {
        match msg {
            WsData::Text(text) => {
                let _ = conn.send_text(&text);
            }
            WsData::Binary(bytes) => {
                let _ = conn.send_binary(&bytes);
            }
        }
    }
}

struct App;

impl Handler for App {
    fn handle(&self, _req: Request<Body>) -> Response<Body> {
        Response::with_status(StatusCode::from_u16(404))
    }

    fn websocket(&self, _req: &Request<Body>) -> WsUpgradeReply {
        WsUpgradeReply::Accept(Arc::new(Echo))
    }
}

fn main() -> std::io::Result<()> {
    let addr = std::env::var("WS_AUTOBAHN_ADDR").unwrap_or_else(|_| String::from("0.0.0.0:9001"));
    let config = ServerConfig {
        websocket: WsConfig {
            // See the module note: the suite dials loopback with its own
            // synthetic Origin, so a same-origin check would refuse it.
            origin: OriginPolicy::Any,
            // Compression on, so `12.*`/`13.*` are exercised.
            compression: courierust::courierust_ws::PmDeflatePolicy::default(),
            ..Default::default()
        },
        ..Default::default()
    };
    let server = Server::bind_with_config(&addr, config)?;
    println!("autobahn echo endpoint: ws://{addr}/");
    server.serve(App)
}
