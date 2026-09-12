//! End-to-end WebSocket tests: the real server, the real client and the
//! real (TCP or TLS) transport, plus raw-socket adversarial cases that a
//! friendly client could never produce.
//!
//! The point of these tests is to exercise the *seam*: the opening
//! handshake, the upgrade of a live HTTP/1.1 connection, masking in each
//! direction, the close handshake, compression negotiation, and the
//! policy decisions (origin, subprotocols, limits) — everything that unit
//! tests on either side can only approximate.

use courierust::courierust_body::Body;
use courierust::courierust_client::ws::{WebSocket, WsClientOptions};
use courierust::courierust_client::ClientConfig;
use courierust::courierust_http::header::{HeaderName, HeaderValue};
use courierust::courierust_http::request::Request;
use courierust::courierust_http::response::Response;
use courierust::courierust_http::status::StatusCode;
use courierust::courierust_net::stats::Stats;
use courierust::courierust_server::ws::{
    WsConfig, WsConn, WsData, WsSender, WsService, WsUpgradeReply,
};
use courierust::courierust_server::{Handler, Server, ServerConfig, TlsSettings as ServerTls};
use courierust::courierust_ws::{Event, OriginPolicy};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

mod common;

// ---------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------

/// Serves `/echo` (and any other path the test uses) with a fixed
/// service.
struct WsHandler {
    path: String,
    service: Arc<dyn WsService>,
}

impl Handler for WsHandler {
    fn handle(&self, _req: Request<Body>) -> Response<Body> {
        let mut resp: Response<Body> = Response::with_status(StatusCode::from_u16(404));
        resp.headers.insert(
            HeaderName::from_static("content-type"),
            HeaderValue::from_static("text/plain"),
        );
        resp.body = Body::Bytes(courierust::Bytes::from_static(b"no websocket here\n"));
        resp
    }

    fn websocket(&self, req: &Request<Body>) -> WsUpgradeReply {
        if req.uri.path() == self.path {
            WsUpgradeReply::Accept(self.service.clone())
        } else {
            WsUpgradeReply::Pass
        }
    }
}

/// Start a server and return its address. The handle is leaked so the
/// server outlives the test body.
fn spawn_ws_server(config: ServerConfig, path: &str, service: Arc<dyn WsService>) -> SocketAddr {
    let server = Server::bind_with_config("127.0.0.1:0", config).expect("bind");
    let addr = server.local_addr().expect("addr");
    let handle = server
        .serve_background(WsHandler {
            path: String::from(path),
            service,
        })
        .expect("serve");
    std::mem::forget(handle);
    addr
}

/// The blocking driver (used for TLS and for `event_driven = false`).
fn blocking_config() -> ServerConfig {
    ServerConfig {
        event_driven: false,
        threads: 4,
        ..Default::default()
    }
}

/// Echoes every message back, recording counters the tests can inspect.
#[derive(Default)]
struct EchoService {
    text: Mutex<Vec<String>>,
    binary: Mutex<Vec<Vec<u8>>>,
    opened: Mutex<usize>,
    closed: Mutex<Vec<(Option<u16>, bool)>>,
}

impl WsService for EchoService {
    fn on_open(&self, c: &mut WsConn) {
        *self.opened.lock().unwrap() += 1;
        // Per-connection state, attached without a service per
        // connection.
        c.set_state(String::from("session-state"));
    }

    fn on_message(&self, c: &mut WsConn, msg: WsData) {
        match msg {
            WsData::Text(t) => {
                assert_eq!(
                    c.with_state::<String, _>(|s| s.clone()).as_deref(),
                    Some("session-state")
                );
                self.text.lock().unwrap().push(t.clone());
                let _ = c.send_text(&t);
            }
            WsData::Binary(b) => {
                self.binary.lock().unwrap().push(b.to_vec());
                let _ = c.send_binary(&b);
            }
        }
    }

    fn on_close(&self, _c: &mut WsConn, code: Option<u16>, clean: bool) {
        self.closed.lock().unwrap().push((code, clean));
    }
}

fn wait_for<F: Fn() -> bool>(what: &str, f: F) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        if f() {
            return;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    panic!("timed out waiting for {what}");
}

fn connect(addr: SocketAddr, path: &str) -> WebSocket {
    let cfg = ClientConfig::default();
    WebSocket::connect(&format!("ws://{addr}{path}"), &cfg).expect("handshake")
}

/// Connect with a short read deadline, so a stalled server fails a test
/// in seconds and with an error that names the cause instead of hiding
/// behind the default minute-long timeout.
fn connect_within(addr: SocketAddr, path: &str, read_timeout: Duration) -> WebSocket {
    let cfg = ClientConfig {
        read_timeout: Some(read_timeout),
        ..ClientConfig::default()
    };
    WebSocket::connect(&format!("ws://{addr}{path}"), &cfg).expect("handshake")
}

// ---------------------------------------------------------------------
// Happy paths
// ---------------------------------------------------------------------

#[test]
fn echo_roundtrip_blocking_driver() {
    let service = Arc::new(EchoService::default());
    let observed = service.clone();
    let addr = spawn_ws_server(blocking_config(), "/echo", service);
    let mut ws = connect(addr, "/echo");

    ws.send_text("hello").unwrap();
    ws.send_text("日本語 🦀").unwrap();
    ws.send_binary(&[0u8, 1, 2, 255]).unwrap();

    assert_eq!(
        ws.read_message().unwrap(),
        Event::Text(String::from("hello"))
    );
    assert_eq!(
        ws.read_message().unwrap(),
        Event::Text(String::from("日本語 🦀"))
    );
    assert_eq!(
        ws.read_message().unwrap(),
        Event::Binary(courierust::Bytes::from(&[0u8, 1, 2, 255][..]))
    );

    assert_eq!(observed.text.lock().unwrap().len(), 2);
    assert_eq!(observed.binary.lock().unwrap().len(), 1);
    assert_eq!(*observed.opened.lock().unwrap(), 1);

    ws.close(1000, "done").unwrap();
    wait_for("the server to observe the close", || {
        !observed.closed.lock().unwrap().is_empty()
    });
    let closed = observed.closed.lock().unwrap().clone();
    assert_eq!(closed[0].0, Some(1000));
    assert!(closed[0].1, "the closing handshake must be clean");
}

#[test]
fn large_messages_survive_the_round_trip() {
    let addr = spawn_ws_server(blocking_config(), "/echo", Arc::new(EchoService::default()));
    let mut ws = connect(addr, "/echo");

    // 1 MiB of semi-compressible binary data (exercise the 64-bit length
    // form, the masking windows and the reassembly buffers at once).
    let big: Vec<u8> = (0..1024 * 1024).map(|i| (i % 251) as u8).collect();
    ws.send_binary(&big).unwrap();
    match ws.read_message().unwrap() {
        Event::Binary(b) => assert_eq!(b.as_slice(), &big[..]),
        other => panic!("unexpected {other:?}"),
    }

    // A text message large enough to span many read buffers.
    let text = "The quick brown fox jumps over the lazy dog. ".repeat(4096);
    ws.send_text(&text).unwrap();
    assert_eq!(ws.read_message().unwrap(), Event::Text(text));
}

#[test]
fn fragmented_client_frames_are_reassembled() {
    let service = Arc::new(EchoService::default());
    let observed = service.clone();
    let addr = spawn_ws_server(blocking_config(), "/echo", service);

    // A raw client that fragments one text message into three frames with
    // a ping interleaved in the middle.
    let mut raw = raw_handshake(addr, "/echo");
    raw.write_all(&masked_frame(0x1, b"frag", false)).unwrap();
    raw.write_all(&masked_frame(0x9, b"ping", true)).unwrap(); // ping
    raw.write_all(&masked_frame(0x0, b"ment", false)).unwrap();
    raw.write_all(&masked_frame(0x0, b"ed", true)).unwrap();
    raw.flush().unwrap();

    // The ping is answered, then the echo of the complete message.
    raw.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let pong = read_frame(&mut raw);
    assert_eq!(pong.0, 0xA, "expected a Pong for the Ping");
    assert_eq!(pong.1, b"ping");
    let echo = read_frame(&mut raw);
    assert_eq!(echo.0, 0x1);
    assert_eq!(echo.1, b"fragmented");
    wait_for("the server to record the message", || {
        !observed.text.lock().unwrap().is_empty()
    });
}

#[test]
fn server_can_push_from_another_thread() {
    struct PushService {
        sender: Mutex<Option<WsSender>>,
    }
    impl WsService for PushService {
        fn on_open(&self, c: &mut WsConn) {
            *self.sender.lock().unwrap() = Some(c.sender());
        }
    }

    let service = Arc::new(PushService {
        sender: Mutex::new(None),
    });
    let addr = spawn_ws_server(blocking_config(), "/push", service.clone());
    let mut ws = connect(addr, "/push");
    wait_for("the service to publish its sender", || {
        service.sender.lock().unwrap().is_some()
    });

    // Push from the test thread while the connection's owner thread is
    // parked in its read loop.
    let sender = service.sender.lock().unwrap().clone().unwrap();
    sender.send_text("pushed from another thread").unwrap();

    assert_eq!(
        ws.read_message().unwrap(),
        Event::Text(String::from("pushed from another thread"))
    );
}

/// RFC 6455 §5.5.1: once a Close frame has gone out, nothing may follow
/// it — including a push from an application thread that was already in
/// flight. The refusal is the *point*: writing it would be a protocol
/// violation the peer is entitled to fail the connection over.
#[test]
fn a_push_after_close_is_refused() {
    struct CloseOnMessage {
        sender: Mutex<Option<WsSender>>,
    }
    impl WsService for CloseOnMessage {
        fn on_open(&self, c: &mut WsConn) {
            *self.sender.lock().unwrap() = Some(c.sender());
        }
        fn on_message(&self, c: &mut WsConn, _msg: WsData) {
            let _ = c.close(1000, "closing");
        }
    }

    let service = Arc::new(CloseOnMessage {
        sender: Mutex::new(None),
    });
    let addr = spawn_ws_server(blocking_config(), "/closing", service.clone());
    let mut ws = connect(addr, "/closing");
    wait_for("the service to publish its sender", || {
        service.sender.lock().unwrap().is_some()
    });
    let sender = service.sender.lock().unwrap().clone().unwrap();

    ws.send_text("please close").unwrap();
    match ws.read_message().unwrap() {
        Event::Close(frame) => assert_eq!(frame.map(|f| f.code), Some(1000)),
        other => panic!("unexpected {other:?}"),
    }

    let err = sender.send_text("too late").unwrap_err();
    assert_eq!(
        err.kind,
        courierust::courierust_error::ErrorKind::Canceled,
        "{err}"
    );
    assert!(sender.send_binary(b"too late").is_err());
    assert!(
        sender.close(1000, "again").is_ok(),
        "a second close is a no-op"
    );
}

#[test]
fn ping_and_pong_are_exchanged() {
    let addr = spawn_ws_server(blocking_config(), "/echo", Arc::new(EchoService::default()));
    let mut ws = connect(addr, "/echo");
    ws.send_ping(b"are you there").unwrap();
    match ws.read_message().unwrap() {
        Event::Pong(payload) => assert_eq!(payload.as_slice(), b"are you there"),
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn per_message_deflate_round_trips_through_the_stack() {
    let service = Arc::new(EchoService::default());
    let observed = service.clone();
    let addr = spawn_ws_server(blocking_config(), "/echo", service);
    let mut ws = connect(addr, "/echo");
    assert!(
        ws.compression().is_some(),
        "the client offers permessage-deflate and the server accepts it"
    );

    let text = "compress me ".repeat(500);
    ws.send_text(&text).unwrap();
    let echoed = ws.read_message().unwrap();
    assert_eq!(echoed, Event::Text(text));
    let stats = ws.stats();
    assert!(stats.compressed_written >= 1);
    assert!(stats.compressed_read >= 1);
    assert!(stats.bytes_saved_written > 0);
    assert_eq!(observed.text.lock().unwrap().len(), 1);
}

#[test]
fn subprotocols_are_negotiated_by_server_preference() {
    let config = ServerConfig {
        websocket: WsConfig {
            subprotocols: vec![String::from("chat.v1"), String::from("chat.v2")],
            ..Default::default()
        },
        ..blocking_config()
    };
    let addr = spawn_ws_server(config, "/echo", Arc::new(EchoService::default()));
    let cfg = ClientConfig::default();
    let opts = WsClientOptions {
        protocols: vec![String::from("chat.v1"), String::from("chat.v2")],
        require_subprotocol: true,
        ..Default::default()
    };
    let mut ws = WebSocket::connect_with(&format!("ws://{addr}/echo"), &cfg, &opts).unwrap();
    assert_eq!(
        ws.protocol(),
        Some("chat.v1"),
        "first offered wins by default"
    );
    ws.send_text("hi").unwrap();
    assert_eq!(ws.read_message().unwrap(), Event::Text(String::from("hi")));

    // A client that offers only an unsupported protocol is told so:
    // nothing is selected, and `require_subprotocol` turns that into an
    // error instead of a silently degraded connection.
    let opts = WsClientOptions {
        protocols: vec![String::from("nope.v9")],
        require_subprotocol: true,
        ..Default::default()
    };
    assert!(WebSocket::connect_with(&format!("ws://{addr}/echo"), &cfg, &opts).is_err());
}

#[test]
fn a_second_connection_reuses_the_server_without_interference() {
    let addr = spawn_ws_server(blocking_config(), "/echo", Arc::new(EchoService::default()));
    let mut a = connect(addr, "/echo");
    let mut b = connect(addr, "/echo");
    a.send_text("for a").unwrap();
    b.send_text("for b").unwrap();
    assert_eq!(
        a.read_message().unwrap(),
        Event::Text(String::from("for a"))
    );
    assert_eq!(
        b.read_message().unwrap(),
        Event::Text(String::from("for b"))
    );
}

// ---------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------

#[test]
fn cross_origin_upgrades_are_refused_by_default() {
    let addr = spawn_ws_server(blocking_config(), "/echo", Arc::new(EchoService::default()));
    let cfg = ClientConfig::default();
    let opts = WsClientOptions {
        origin: Some(String::from("https://evil.test")),
        ..Default::default()
    };
    let err = match WebSocket::connect_with(&format!("ws://{addr}/echo"), &cfg, &opts) {
        Ok(_) => panic!("a cross-origin upgrade must be refused"),
        Err(e) => e,
    };
    assert!(err.to_string().contains("403"), "{err}");
}

#[test]
fn same_origin_upgrades_are_accepted() {
    let addr = spawn_ws_server(blocking_config(), "/echo", Arc::new(EchoService::default()));
    let cfg = ClientConfig::default();
    let opts = WsClientOptions {
        origin: Some(format!("http://{addr}")),
        ..Default::default()
    };
    let mut ws = WebSocket::connect_with(&format!("ws://{addr}/echo"), &cfg, &opts).unwrap();
    ws.send_text("same origin").unwrap();
    assert_eq!(
        ws.read_message().unwrap(),
        Event::Text(String::from("same origin"))
    );
}

#[test]
fn an_allow_list_admits_exactly_the_listed_origin() {
    let config = ServerConfig {
        websocket: WsConfig {
            origin: OriginPolicy::list(["https://app.example.com"]),
            ..Default::default()
        },
        ..blocking_config()
    };
    let addr = spawn_ws_server(config, "/echo", Arc::new(EchoService::default()));
    let cfg = ClientConfig::default();

    let ok = WsClientOptions {
        origin: Some(String::from("https://app.example.com")),
        ..Default::default()
    };
    assert!(WebSocket::connect_with(&format!("ws://{addr}/echo"), &cfg, &ok).is_ok());

    let bad = WsClientOptions {
        origin: Some(String::from("https://app.example.com.evil.test")),
        ..Default::default()
    };
    assert!(WebSocket::connect_with(&format!("ws://{addr}/echo"), &cfg, &bad).is_err());
}

#[test]
fn the_upgrade_path_is_per_route() {
    let addr = spawn_ws_server(blocking_config(), "/echo", Arc::new(EchoService::default()));
    let cfg = ClientConfig::default();
    // `/other` is not a WebSocket route: the handler falls through to
    // normal HTTP, which answers 404 and never switches protocols.
    let err = match WebSocket::connect(&format!("ws://{addr}/other"), &cfg) {
        Ok(_) => panic!("a non-WebSocket route must not upgrade"),
        Err(e) => e,
    };
    assert!(err.to_string().contains("404"), "{err}");
}

#[test]
fn a_disabled_websocket_upgrade_falls_through_to_http() {
    let config = ServerConfig {
        websocket: WsConfig {
            enabled: false,
            ..Default::default()
        },
        ..blocking_config()
    };
    let addr = spawn_ws_server(config, "/echo", Arc::new(EchoService::default()));
    let err = match WebSocket::connect(&format!("ws://{addr}/echo"), &ClientConfig::default()) {
        Ok(_) => panic!("websockets are disabled"),
        Err(e) => e,
    };
    // With websockets off the request is ordinary HTTP: the handler's
    // own 404 is what the client sees, not a protocol switch.
    assert!(err.to_string().contains("404"), "{err}");
}

// ---------------------------------------------------------------------
// Limits and adversarial input
// ---------------------------------------------------------------------

#[test]
fn an_oversized_message_is_closed_with_1009() {
    let config = ServerConfig {
        websocket: WsConfig {
            max_message: 1024,
            max_frame: 1024,
            ..Default::default()
        },
        ..blocking_config()
    };
    let addr = spawn_ws_server(config, "/echo", Arc::new(EchoService::default()));
    let mut raw = raw_handshake(addr, "/echo");
    raw.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    // One frame over the frame limit: the server must refuse before it
    // buffers the payload.
    raw.write_all(&masked_frame(0x2, &vec![0u8; 2048], true))
        .unwrap();
    raw.flush().unwrap();
    let (opcode, payload) = read_frame(&mut raw);
    assert_eq!(opcode, 0x8, "expected a Close frame");
    assert_eq!(u16::from_be_bytes([payload[0], payload[1]]), 1009);
}

#[test]
fn an_unmasked_client_frame_is_closed_with_1002() {
    let addr = spawn_ws_server(blocking_config(), "/echo", Arc::new(EchoService::default()));
    let mut raw = raw_handshake(addr, "/echo");
    raw.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    // RFC 6455 §5.1: a server MUST fail the connection on an unmasked
    // client frame.
    raw.write_all(&unmasked_frame(0x1, b"cheeky", true))
        .unwrap();
    raw.flush().unwrap();
    let (opcode, payload) = read_frame(&mut raw);
    assert_eq!(opcode, 0x8);
    assert_eq!(u16::from_be_bytes([payload[0], payload[1]]), 1002);
}

#[test]
fn invalid_utf8_in_a_text_frame_is_closed_with_1007() {
    let addr = spawn_ws_server(blocking_config(), "/echo", Arc::new(EchoService::default()));
    let mut raw = raw_handshake(addr, "/echo");
    raw.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    raw.write_all(&masked_frame(0x1, &[0x41, 0xff, 0x42], true))
        .unwrap();
    raw.flush().unwrap();
    let (opcode, payload) = read_frame(&mut raw);
    assert_eq!(opcode, 0x8);
    assert_eq!(u16::from_be_bytes([payload[0], payload[1]]), 1007);
}

#[test]
fn reserved_bits_and_bad_opcodes_are_closed_with_1002() {
    // RSV1 without a negotiated extension.
    let addr = spawn_ws_server(blocking_config(), "/echo", Arc::new(EchoService::default()));
    let mut raw = raw_handshake(addr, "/echo");
    raw.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut frame = masked_frame(0x1, b"x", true);
    frame[0] |= 0x40; // RSV1
    raw.write_all(&frame).unwrap();
    raw.flush().unwrap();
    let (opcode, payload) = read_frame(&mut raw);
    assert_eq!(opcode, 0x8);
    assert_eq!(u16::from_be_bytes([payload[0], payload[1]]), 1002);

    // Reserved opcode 0x3.
    let addr = spawn_ws_server(blocking_config(), "/echo", Arc::new(EchoService::default()));
    let mut raw = raw_handshake(addr, "/echo");
    raw.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    raw.write_all(&masked_frame(0x3, b"x", true)).unwrap();
    raw.flush().unwrap();
    let (opcode, payload) = read_frame(&mut raw);
    assert_eq!(opcode, 0x8);
    assert_eq!(u16::from_be_bytes([payload[0], payload[1]]), 1002);
}

#[test]
fn a_non_minimal_length_encoding_is_closed_with_1002() {
    let addr = spawn_ws_server(blocking_config(), "/echo", Arc::new(EchoService::default()));
    let mut raw = raw_handshake(addr, "/echo");
    raw.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    // "hello" in a frame that advertises a 16-bit length it does not
    // need. A parser that accepts this disagrees with a strict proxy
    // about where the frame ends.
    let mut frame = vec![0x81u8, 0x80 | 126, 0x00, 0x05, 1, 2, 3, 4];
    let mut body = b"hello".to_vec();
    mask_in_place(&mut body, [1, 2, 3, 4]);
    frame.extend_from_slice(&body);
    raw.write_all(&frame).unwrap();
    raw.flush().unwrap();
    let (opcode, payload) = read_frame(&mut raw);
    assert_eq!(opcode, 0x8);
    assert_eq!(u16::from_be_bytes([payload[0], payload[1]]), 1002);
}

#[test]
fn a_hostile_client_cannot_stall_the_server_with_a_partial_frame() {
    let config = ServerConfig {
        websocket: WsConfig {
            ping_interval: Some(Duration::from_millis(200)),
            ..Default::default()
        },
        ..blocking_config()
    };
    let addr = spawn_ws_server(config, "/echo", Arc::new(EchoService::default()));
    let mut raw = raw_handshake(addr, "/echo");
    raw.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    // Half a frame header, then silence. The driver's keepalive must
    // eventually close the connection instead of holding it forever.
    raw.write_all(&[0x81]).unwrap();
    raw.flush().unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut saw_eof_or_close = false;
    while std::time::Instant::now() < deadline {
        let mut buf = [0u8; 64];
        match raw.read(&mut buf) {
            Ok(0) => {
                saw_eof_or_close = true;
                break;
            }
            Ok(_) => {
                if buf[0] == 0x88 {
                    saw_eof_or_close = true;
                }
            }
            Err(_) => break,
        }
    }
    assert!(
        saw_eof_or_close,
        "the connection must not stay open forever"
    );
}

// ---------------------------------------------------------------------
// The default (event-driven) server
// ---------------------------------------------------------------------

/// The default server configuration: plain HTTP/1.1 connections are
/// handled by the event reactor, and an accepted upgrade keeps the
/// connection in that reactor — no thread is spent per WebSocket.
fn event_config() -> ServerConfig {
    ServerConfig {
        event_driven: true,
        event_workers: 2,
        threads: 2,
        ..Default::default()
    }
}

#[test]
fn echo_roundtrip_on_the_event_driven_server() {
    let service = Arc::new(EchoService::default());
    let observed = service.clone();
    let addr = spawn_ws_server(event_config(), "/echo", service);
    let mut ws = connect(addr, "/echo");

    ws.send_text("via the reactor").unwrap();
    assert_eq!(
        ws.read_message().unwrap(),
        Event::Text(String::from("via the reactor"))
    );
    ws.send_binary(&[7u8; 4096]).unwrap();
    match ws.read_message().unwrap() {
        Event::Binary(b) => assert_eq!(b.len(), 4096),
        other => panic!("unexpected {other:?}"),
    }
    // A large message exercises the queued write path across many poll
    // iterations.
    let big = "x".repeat(512 * 1024);
    ws.send_text(&big).unwrap();
    assert_eq!(ws.read_message().unwrap(), Event::Text(big));

    ws.close(1000, "bye").unwrap();
    wait_for("the reactor to observe the close", || {
        !observed.closed.lock().unwrap().is_empty()
    });
    let closed = observed.closed.lock().unwrap().clone();
    assert!(
        closed[0].1,
        "the closing handshake must be clean: {closed:?}"
    );
}

#[test]
fn the_event_server_pushes_from_another_thread() {
    struct PushService {
        sender: Mutex<Option<WsSender>>,
    }
    impl WsService for PushService {
        fn on_open(&self, c: &mut WsConn) {
            *self.sender.lock().unwrap() = Some(c.sender());
        }
    }

    let service = Arc::new(PushService {
        sender: Mutex::new(None),
    });
    let addr = spawn_ws_server(event_config(), "/push", service.clone());
    let mut ws = connect(addr, "/push");
    wait_for("the service to publish its sender", || {
        service.sender.lock().unwrap().is_some()
    });
    let sender = service.sender.lock().unwrap().clone().unwrap();

    // The connection is parked in the reactor: this push has to travel
    // through the queue *and* the reactor's wakeup to arrive.
    for i in 0..8 {
        sender.send_text(&format!("push {i}")).unwrap();
    }
    for i in 0..8 {
        assert_eq!(
            ws.read_message().unwrap(),
            Event::Text(format!("push {i}")),
            "pushed messages must arrive in order"
        );
    }
}

#[test]
fn many_connections_echo_concurrently() {
    let addr = spawn_ws_server(event_config(), "/echo", Arc::new(EchoService::default()));
    let mut handles = Vec::new();
    for i in 0..12 {
        handles.push(std::thread::spawn(move || {
            let mut ws = connect(addr, "/echo");
            for round in 0..8 {
                let text = format!("conn {i} round {round}");
                ws.send_text(&text).unwrap();
                assert_eq!(ws.read_message().unwrap(), Event::Text(text));
            }
            ws.close(1000, "done").unwrap();
        }));
    }
    for h in handles {
        h.join().expect("worker thread");
    }
}

/// Regression: a connection that ends must leave the reactor's wait set.
///
/// The descriptor of a closed connection used to stay registered, so the
/// reactor kept waiting on a socket nobody owned any more. Where the
/// platform rejects a whole wait set for one bad descriptor (Winsock's
/// `select` fails with `WSAENOTSOCK`), the reactor then failed every
/// wait from that moment on — every other connection stayed parked until
/// its peer gave up, which is exactly what a busy server must never do.
///
/// The test does not merely check that the closed connection is gone; it
/// proves the *survivors* keep talking.
#[test]
fn a_closed_connection_does_not_stop_the_reactor() {
    let service = Arc::new(EchoService::default());
    let observed = service.clone();
    // The reactor's own evidence: a healthy run never pays a failed wait.
    let stats = Stats::new();
    let addr = spawn_ws_server(
        ServerConfig {
            stats: Some(stats.clone()),
            ..event_config()
        },
        "/echo",
        service,
    );
    let deadline = Duration::from_secs(5);
    let mut leaving = connect_within(addr, "/echo", deadline);
    let mut staying = connect_within(addr, "/echo", deadline);

    // Both connections are live on the same reactor before one leaves.
    leaving.send_text("leaving").unwrap();
    staying.send_text("staying").unwrap();
    assert_eq!(
        leaving.read_message().unwrap(),
        Event::Text(String::from("leaving"))
    );
    assert_eq!(
        staying.read_message().unwrap(),
        Event::Text(String::from("staying"))
    );

    // Close one of them and wait until the server has seen it end, so the
    // close is really processed while the other connection is parked.
    leaving.close(1000, "bye").unwrap();
    drop(leaving);
    wait_for("the server to observe the close", || {
        !observed.closed.lock().unwrap().is_empty()
    });

    for round in 0..4 {
        let text = format!("still here {round}");
        staying.send_text(&text).unwrap();
        assert_eq!(
            staying.read_message().unwrap(),
            Event::Text(text),
            "the reactor must keep serving the connections that are still open"
        );
    }
    staying.close(1000, "done").unwrap();

    // The invariant behind that: every close unregisters the descriptor
    // *before* it is closed, so no wait ever names a closed one and the
    // reactor never has to recover at all.
    let snapshot = stats.snapshot();
    assert_eq!(
        snapshot.event_wait_errors, 0,
        "a healthy reactor never pays a failed wait"
    );
    assert!(
        snapshot.event_poll_syscalls > 0,
        "the reactor must have waited at least once"
    );
}

#[test]
fn an_upgrade_and_plain_http_share_the_same_server() {
    let addr = spawn_ws_server(event_config(), "/echo", Arc::new(EchoService::default()));
    // Plain HTTP still works on the event server alongside WebSockets.
    let mut http = TcpStream::connect(addr).unwrap();
    http.write_all(
        format!("GET /health HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .unwrap();
    let mut response = String::new();
    http.read_to_string(&mut response).unwrap();
    assert!(response.starts_with("HTTP/1.1 404"), "{response}");

    // ...and so does WebSocket.
    let mut ws = connect(addr, "/echo");
    ws.send_text("still works").unwrap();
    assert_eq!(
        ws.read_message().unwrap(),
        Event::Text(String::from("still works"))
    );
}

#[test]
fn the_event_reactor_enforces_limits_too() {
    let config = ServerConfig {
        websocket: WsConfig {
            max_message: 4096,
            ..Default::default()
        },
        ..event_config()
    };
    let addr = spawn_ws_server(config, "/echo", Arc::new(EchoService::default()));
    let mut ws = connect(addr, "/echo");
    // An 8 KiB binary message against a 4 KiB limit. The server must
    // refuse it *before* buffering the payload, and the client sees that
    // as a `1009` close (the close frame is the last thing that arrives).
    ws.send_binary(&vec![0u8; 8192]).unwrap();
    match ws.read_message() {
        Ok(Event::Close(Some(frame))) => assert_eq!(frame.code, 1009),
        Ok(other) => panic!("expected a 1009 close, got {other:?}"),
        Err(e) => assert!(
            e.kind == courierust::ErrorKind::Overflow || e.to_string().contains("size limit"),
            "{e}"
        ),
    }
}

// ---------------------------------------------------------------------
// TLS / WSS
// ---------------------------------------------------------------------

#[test]
fn wss_round_trip_over_tls() {
    let config = ServerConfig {
        tls: Some(ServerTls {
            identity: common::server_identity(),
            alpn: vec![b"http/1.1".to_vec()],
            ..Default::default()
        }),
        ..blocking_config()
    };
    let addr = spawn_ws_server(config, "/echo", Arc::new(EchoService::default()));

    let cfg = ClientConfig {
        tls: Some(courierust::courierust_client::TlsSettings {
            roots: common::root_store(),
            verify: true,
            alpn: vec![b"http/1.1".to_vec()],
            now: common::NOW,
            min_version: courierust::courierust_tls::TlsVersion::Tls12,
            max_version: courierust::courierust_tls::TlsVersion::Tls13,
        }),
        ..Default::default()
    };
    let mut ws = WebSocket::connect(&format!("wss://localhost:{}/echo", addr.port()), &cfg)
        .expect("wss handshake");
    assert!(ws.info().secure);

    ws.send_text("over tls").unwrap();
    assert_eq!(
        ws.read_message().unwrap(),
        Event::Text(String::from("over tls"))
    );
    ws.send_binary(&[9u8; 100_000]).unwrap();
    match ws.read_message().unwrap() {
        Event::Binary(b) => assert_eq!(b.len(), 100_000),
        other => panic!("unexpected {other:?}"),
    }
    ws.close(1000, "bye").unwrap();
}

// ---------------------------------------------------------------------
// Raw-socket helpers (a client that does not use our code)
// ---------------------------------------------------------------------

/// Perform the opening handshake by hand and return the socket.
fn raw_handshake(addr: SocketAddr, path: &str) -> TcpStream {
    let mut sock = TcpStream::connect(addr).expect("connect");
    sock.set_nodelay(true).ok();
    sock.set_read_timeout(Some(Duration::from_secs(10))).ok();
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {addr}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    sock.write_all(request.as_bytes()).unwrap();
    sock.flush().unwrap();

    // Read until the end of the response head.
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        let n = sock.read(&mut byte).expect("read response head");
        assert_ne!(n, 0, "server closed during the handshake");
        head.push(byte[0]);
    }
    let text = String::from_utf8_lossy(&head).to_string();
    assert!(text.starts_with("HTTP/1.1 101"), "handshake failed: {text}");
    sock
}

fn mask_in_place(payload: &mut [u8], key: [u8; 4]) {
    for (i, b) in payload.iter_mut().enumerate() {
        *b ^= key[i & 3];
    }
}

/// A client-to-server frame (masked, as RFC 6455 requires).
fn masked_frame(opcode: u8, payload: &[u8], fin: bool) -> Vec<u8> {
    let key = [0x21, 0x22, 0x23, 0x24];
    let mut out = Vec::new();
    out.push(if fin { 0x80 | opcode } else { opcode });
    let len = payload.len();
    if len < 126 {
        out.push(0x80 | len as u8);
    } else if len <= u16::MAX as usize {
        out.push(0x80 | 126);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(0x80 | 127);
        out.extend_from_slice(&(len as u64).to_be_bytes());
    }
    out.extend_from_slice(&key);
    let mut body = payload.to_vec();
    mask_in_place(&mut body, key);
    out.extend_from_slice(&body);
    out
}

/// A frame with the mask bit clear (only legal from a server).
fn unmasked_frame(opcode: u8, payload: &[u8], fin: bool) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(if fin { 0x80 | opcode } else { opcode });
    assert!(payload.len() < 126);
    out.push(payload.len() as u8);
    out.extend_from_slice(payload);
    out
}

/// Read one server-to-client frame (unmasked, as RFC 6455 requires).
fn read_frame(sock: &mut TcpStream) -> (u8, Vec<u8>) {
    let mut head = [0u8; 2];
    sock.read_exact(&mut head).expect("frame header");
    let opcode = head[0] & 0x0f;
    assert_eq!(head[1] & 0x80, 0, "server frames must not be masked");
    let len = match head[1] & 0x7f {
        126 => {
            let mut b = [0u8; 2];
            sock.read_exact(&mut b).unwrap();
            u16::from_be_bytes(b) as usize
        }
        127 => {
            let mut b = [0u8; 8];
            sock.read_exact(&mut b).unwrap();
            u64::from_be_bytes(b) as usize
        }
        n => n as usize,
    };
    let mut payload = vec![0u8; len];
    sock.read_exact(&mut payload).expect("frame payload");
    (opcode, payload)
}
