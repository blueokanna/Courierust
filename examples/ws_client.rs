//! A WebSocket **client** against any server, including a `wss://` one,
//! with the options that matter in production: subprotocols, an Origin
//! header, compression preference, read deadlines, and a bounded close.
//!
//! ```text
//! # echo against a public echo server
//! cargo run --example ws_client -- wss://echo.websocket.org/
//!
//! # keep the connection open and read server pushes
//! cargo run --example ws_client -- wss://example.com/feed --listen
//! ```

use courierust::courierust_client::ws::{WebSocket, WsClientOptions};
use courierust::courierust_client::ClientConfig;
use courierust::courierust_ws::Event;
use std::time::{Duration, Instant};

fn main() -> courierust::Result<()> {
    let mut args = std::env::args().skip(1);
    let mut url = None;
    let mut listen = false;
    let mut insecure = false;
    for arg in args.by_ref() {
        match arg.as_str() {
            "--listen" => listen = true,
            // Accept the public echo server's certificate chain without a
            // configured root store. Never do this against a real service.
            "--insecure" => insecure = true,
            other => url = Some(other.to_string()),
        }
    }
    let url = url.unwrap_or_else(|| "wss://echo.websocket.org/".to_string());

    let opts = WsClientOptions {
        protocols: vec!["echo".into()],
        require_subprotocol: false,
        compression: true,
        origin: Some("https://example.com".to_string()),
        ..Default::default()
    };

    let mut cfg = ClientConfig {
        read_timeout: Some(Duration::from_secs(30)),
        ..Default::default()
    };
    if insecure {
        cfg.tls = Some(courierust::courierust_client::TlsSettings {
            verify: false,
            ..Default::default()
        });
    }

    let mut ws = WebSocket::connect_with(&url, &cfg, &opts)?;
    let info = ws.info();
    println!(
        "connected to {url}\n  protocol   = {:?}\n  compression= {:?}\n  secure     = {}",
        info.protocol, info.compression, info.secure
    );

    ws.send_text("hello from courierust")?;
    let start = Instant::now();
    match ws.read_message()? {
        Event::Text(t) => println!("echo   -> {t:?} ({:?})", start.elapsed()),
        other => println!("unexpected: {other:?}"),
    }

    if listen {
        println!("listening for pushes; Ctrl+C to stop");
        loop {
            match ws.read_message() {
                Ok(Event::Ping(p)) => {
                    println!("ping {:?}", p.as_ref());
                }
                Ok(Event::Pong(p)) => println!("pong {:?}", p.as_ref()),
                Ok(Event::Text(t)) => println!("push {:?}", t),
                Ok(Event::Binary(b)) => println!("push {} binary bytes", b.len()),
                Ok(Event::Close(frame)) => {
                    println!("peer closed: {frame:?}");
                    break;
                }
                Err(e) => {
                    println!("read failed: {e}");
                    break;
                }
            }
        }
    }

    println!("stats -> {:?}", ws.stats());
    ws.close(1000, "bye")?;
    Ok(())
}
