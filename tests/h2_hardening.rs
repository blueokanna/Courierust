//! HTTP/2 hardening integration tests: malformed / hostile frame inputs,
//! the RFC 7540 §3.2 `h2c` Upgrade handshake, SETTINGS_TIMEOUT and
//! keepalive dead-peer detection — all against a real loopback server.

mod common;

use courierust::body::Body;
use courierust::bytes::Bytes;
use courierust::client::{Client, ClientConfig};
use courierust::http::header::{HeaderName, HeaderValue};
use courierust::http::method::Method;
use courierust::http::request::Request;
use courierust::server::{Server, ServerConfig};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Build a 9-byte h2 frame header.
fn frame_header(len: u32, kind: u8, flags: u8, stream_id: u32) -> [u8; 9] {
    let mut h = [0u8; 9];
    h[0] = (len >> 16) as u8;
    h[1] = (len >> 8) as u8;
    h[2] = len as u8;
    h[3] = kind;
    h[4] = flags;
    let sid = stream_id & 0x7fff_ffff;
    h[5] = (sid >> 24) as u8;
    h[6] = (sid >> 16) as u8;
    h[7] = (sid >> 8) as u8;
    h[8] = sid as u8;
    h
}

/// A minimal, valid SETTINGS frame (one entry).
fn settings_frame() -> Vec<u8> {
    let mut f = frame_header(6, 0x4, 0, 0).to_vec();
    f.extend_from_slice(&0x0004u16.to_be_bytes()); // INITIAL_WINDOW_SIZE
    f.extend_from_slice(&65535u32.to_be_bytes());
    f
}

/// HPACK-encode a header block using the crate's own encoder.
fn hpack(fields: &[(HeaderName, HeaderValue)]) -> Vec<u8> {
    let mut enc = courierust::hpack::Encoder::new();
    let list: Vec<courierust::hpack::HeaderField> = fields
        .iter()
        .map(|(n, v)| courierust::hpack::HeaderField::new(n.clone(), v.clone()))
        .collect();
    let mut out = courierust::bytes::BytesMut::new();
    enc.encode(&list, &mut out);
    out.to_vec()
}

/// A raw h2 peer that speaks crafted frames over a loopback socket.
struct RawH2Peer {
    stream: TcpStream,
}

impl RawH2Peer {
    fn connect(addr: SocketAddr) -> std::io::Result<Self> {
        let stream = TcpStream::connect(addr)?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        Ok(Self { stream })
    }

    fn send(&mut self, bytes: &[u8]) {
        self.stream.write_all(bytes).unwrap();
        self.stream.flush().unwrap();
    }

    /// Send the client connection preface plus our SETTINGS.
    fn send_preface_and_settings(&mut self) {
        let mut buf = Vec::new();
        buf.extend_from_slice(PREFACE);
        buf.extend_from_slice(&settings_frame());
        self.send(&buf);
    }

    /// Send a single raw frame.
    fn send_frame(&mut self, kind: u8, flags: u8, stream_id: u32, payload: &[u8]) {
        let mut buf = frame_header(payload.len() as u32, kind, flags, stream_id).to_vec();
        buf.extend_from_slice(payload);
        self.send(&buf);
    }

    /// Read one frame; returns (kind, flags, stream_id, payload).
    fn read_frame(&mut self) -> Option<(u8, u8, u32, Vec<u8>)> {
        let mut hdr = [0u8; 9];
        if self.stream.read_exact(&mut hdr).is_err() {
            return None;
        }
        let len = ((hdr[0] as usize) << 16) | ((hdr[1] as usize) << 8) | hdr[2] as usize;
        let kind = hdr[3];
        let flags = hdr[4];
        let sid = u32::from_be_bytes([hdr[5] & 0x7f, hdr[6], hdr[7], hdr[8]]);
        let mut payload = vec![0u8; len];
        if len > 0 {
            if self.stream.read_exact(&mut payload).is_err() {
                return None;
            }
        }
        Some((kind, flags, sid, payload))
    }

    /// Consume the 24-byte client connection preface; returns whether it
    /// matched.
    fn read_preface(&mut self) -> bool {
        let mut p = [0u8; 24];
        if self.stream.read_exact(&mut p).is_err() {
            return false;
        }
        &p == PREFACE
    }

    /// Drain frames until a GOAWAY is observed (or the peer closes);
    /// returns the GOAWAY error code when present.
    fn wait_goaway(&mut self, timeout: Duration) -> Option<u32> {
        let start = std::time::Instant::now();
        while start.elapsed() < timeout {
            match self.read_frame() {
                Some((0x7, _, _, payload)) => {
                    if payload.len() >= 8 {
                        return Some(u32::from_be_bytes([
                            payload[4], payload[5], payload[6], payload[7],
                        ]));
                    }
                    return None;
                }
                Some(_) => continue,
                None => return None,
            }
        }
        None
    }
}

/// Spawn an h2 (prior knowledge) server on loopback; returns its address.
fn spawn_h2_server(max_header_list: usize) -> SocketAddr {
    let config = ServerConfig {
        http2: true,
        event_driven: false,
        max_header_list,
        ..Default::default()
    };
    let server = Server::bind_with_config("127.0.0.1:0", config).unwrap();
    let addr = server.local_addr().unwrap();
    let handle = server
        .serve_background(|req: courierust::http::request::Request<Body>| {
            let mut resp = courierust::http::response::Response::<Body>::with_status(200.into());
            let body = req.body.collect().unwrap();
            resp.body = Body::Bytes(body);
            resp
        })
        .unwrap();
    std::mem::forget(handle);
    addr
}

fn hdr(name: &'static str, value: &'static str) -> (HeaderName, HeaderValue) {
    (
        HeaderName::from_lowercase(name),
        HeaderValue::from_static(value),
    )
}

// ---------------------------------------------------------------------
// Malformed / hostile frame inputs
// ---------------------------------------------------------------------

#[test]
fn h2_rejects_oversized_frame_with_goaway() {
    let addr = spawn_h2_server(1 << 20);
    let mut peer = RawH2Peer::connect(addr).unwrap();
    peer.send_preface_and_settings();
    // A frame header claiming a 24-bit max payload (exceeds our 16 KiB
    // max frame size). The length is validated from the header alone, so
    // no payload needs to be sent — and sending megabytes of garbage
    // would trigger a TCP RST that can swallow the GOAWAY.
    peer.send(&frame_header(0x00ff_ffff, 0x1, 0x4, 1));
    // The server must reject with FRAME_SIZE_ERROR (0x6).
    let code = peer.wait_goaway(Duration::from_secs(5));
    assert_eq!(code, Some(0x6), "expected FRAME_SIZE_ERROR GOAWAY");
}

#[test]
fn h2_rejects_settings_not_multiple_of_six() {
    let addr = spawn_h2_server(1 << 20);
    let mut peer = RawH2Peer::connect(addr).unwrap();
    peer.send_preface_and_settings();
    peer.send_frame(0x4, 0, 0, &[0u8; 5]); // SETTINGS with 5-byte payload
    let code = peer.wait_goaway(Duration::from_secs(5));
    assert_eq!(code, Some(0x6), "expected FRAME_SIZE_ERROR GOAWAY");
}

#[test]
fn h2_rejects_ping_wrong_length() {
    let addr = spawn_h2_server(1 << 20);
    let mut peer = RawH2Peer::connect(addr).unwrap();
    peer.send_preface_and_settings();
    peer.send_frame(0x6, 0, 0, &[0u8; 7]); // PING with 7-byte payload
    let code = peer.wait_goaway(Duration::from_secs(5));
    assert_eq!(code, Some(0x6), "expected FRAME_SIZE_ERROR GOAWAY");
}

#[test]
fn h2_rejects_window_update_zero_increment() {
    let addr = spawn_h2_server(1 << 20);
    let mut peer = RawH2Peer::connect(addr).unwrap();
    peer.send_preface_and_settings();
    // WINDOW_UPDATE with increment 0 is a connection error.
    peer.send_frame(0x8, 0, 0, &[0u8; 4]);
    let code = peer.wait_goaway(Duration::from_secs(5));
    assert_eq!(code, Some(0x1), "expected PROTOCOL_ERROR GOAWAY");
}

#[test]
fn h2_rejects_data_on_stream_zero() {
    let addr = spawn_h2_server(1 << 20);
    let mut peer = RawH2Peer::connect(addr).unwrap();
    peer.send_preface_and_settings();
    peer.send_frame(0x0, 0, 0, b"payload"); // DATA on stream 0
    let code = peer.wait_goaway(Duration::from_secs(5));
    assert_eq!(code, Some(0x1), "expected PROTOCOL_ERROR GOAWAY");
}

#[test]
fn h2_rejects_rst_on_idle_stream() {
    let addr = spawn_h2_server(1 << 20);
    let mut peer = RawH2Peer::connect(addr).unwrap();
    peer.send_preface_and_settings();
    // RST_STREAM on a stream that was never opened.
    peer.send_frame(0x3, 0, 3, &0u32.to_be_bytes());
    let code = peer.wait_goaway(Duration::from_secs(5));
    assert_eq!(code, Some(0x1), "expected PROTOCOL_ERROR GOAWAY");
}

#[test]
fn h2_rejects_continuation_without_headers() {
    let addr = spawn_h2_server(1 << 20);
    let mut peer = RawH2Peer::connect(addr).unwrap();
    peer.send_preface_and_settings();
    // CONTINUATION with no preceding HEADERS is a connection error.
    let block = hpack(&[hdr("x-a", "b")]);
    peer.send_frame(0x9, 0x4, 1, &block);
    let code = peer.wait_goaway(Duration::from_secs(5));
    assert_eq!(code, Some(0x1), "expected PROTOCOL_ERROR GOAWAY");
}

#[test]
fn h2_rejects_pseudo_header_after_regular() {
    let addr = spawn_h2_server(1 << 20);
    let mut peer = RawH2Peer::connect(addr).unwrap();
    peer.send_preface_and_settings();
    // A request whose header block puts a regular field before the
    // pseudo-headers (RFC 9113 §8.1.2 violation).
    let block = hpack(&[
        hdr("x-regular", "first"),
        hdr(":method", "GET"),
        hdr(":path", "/"),
        hdr(":scheme", "http"),
    ]);
    peer.send_frame(0x1, 0x4, 1, &block);
    let code = peer.wait_goaway(Duration::from_secs(5));
    assert_eq!(code, Some(0x1), "expected PROTOCOL_ERROR GOAWAY");
}

#[test]
fn h2_rejects_request_missing_pseudo_headers() {
    let addr = spawn_h2_server(1 << 20);
    let mut peer = RawH2Peer::connect(addr).unwrap();
    peer.send_preface_and_settings();
    // A request with only :method (missing :scheme and :path).
    let block = hpack(&[hdr(":method", "GET")]);
    peer.send_frame(0x1, 0x4, 1, &block);
    let code = peer.wait_goaway(Duration::from_secs(5));
    assert_eq!(code, Some(0x1), "expected PROTOCOL_ERROR GOAWAY");
}

#[test]
fn h2_rejects_hpack_header_list_bomb() {
    // A server that advertises a tiny max header list size must reject an
    // oversized header block with COMPRESSION_ERROR.
    let addr = spawn_h2_server(1024);
    let mut peer = RawH2Peer::connect(addr).unwrap();
    peer.send_preface_and_settings();
    let big_value = "x".repeat(8192);
    let block = hpack(&[
        hdr(":method", "GET"),
        hdr(":path", "/"),
        hdr(":scheme", "http"),
        (
            HeaderName::from_lowercase("x-big"),
            HeaderValue::from_bytes(big_value.as_bytes()).unwrap(),
        ),
    ]);
    peer.send_frame(0x1, 0x4, 1, &block);
    let code = peer.wait_goaway(Duration::from_secs(5));
    assert_eq!(code, Some(0x9), "expected COMPRESSION_ERROR GOAWAY");
}

#[test]
fn h2_rejects_unknown_pseudo_header() {
    let addr = spawn_h2_server(1 << 20);
    let mut peer = RawH2Peer::connect(addr).unwrap();
    peer.send_preface_and_settings();
    let block = hpack(&[
        hdr(":method", "GET"),
        hdr(":path", "/"),
        hdr(":scheme", "http"),
        hdr(":bogus", "x"),
    ]);
    peer.send_frame(0x1, 0x4, 1, &block);
    let code = peer.wait_goaway(Duration::from_secs(5));
    assert_eq!(code, Some(0x1), "expected PROTOCOL_ERROR GOAWAY");
}

// ---------------------------------------------------------------------
// Client-side strict response validation
// ---------------------------------------------------------------------

#[test]
fn h2_client_rejects_pseudo_after_regular_response() {
    // A raw server sends a response whose header block has a regular
    // field before :status — the client must treat it as a connection
    // error (RFC 9113 §8.1.2).
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        let (sock, _) = listener.accept().unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut peer = RawH2Peer { stream: sock };
        // Consume the client preface + SETTINGS; reply with our SETTINGS.
        assert!(peer.read_preface());
        let _ = peer.read_frame(); // client SETTINGS
        peer.send_frame(0x4, 0, 0, &[]); // our (empty) SETTINGS
        // Read the client's request HEADERS on stream 1, then respond
        // with a malformed block (regular field before :status).
        loop {
            match peer.read_frame() {
                Some((0x1, _, 1, _)) => break,
                Some((0x4, _, 0, _)) => continue, // client ACK of our SETTINGS
                Some((0x0, _, _, _)) => continue,
                Some(_) => continue,
                None => panic!("client closed before request"),
            }
        }
        let block = hpack(&[hdr("x-regular", "first"), hdr(":status", "200")]);
        peer.send_frame(0x1, 0x4, 1, &block);
        // Keep reading so the connection stays open long enough for the
        // client to observe the violation.
        for _ in 0..200 {
            if peer.read_frame().is_none() {
                break;
            }
        }
    });

    let cfg = ClientConfig {
        http2: true,
        connect_timeout: Some(Duration::from_secs(5)),
        read_timeout: Some(Duration::from_secs(5)),
        h2_settings_timeout: Some(Duration::from_secs(5)),
        h2_ping_interval: None,
        h2_ping_timeout: None,
        h2_idle_timeout: None,
        ..Default::default()
    };
    let client = Client::with_config(cfg);
    let result = client.get(&format!("http://{addr}/"));
    assert!(
        result.is_err(),
        "client must reject a response with a pseudo-header after a regular field"
    );
}

// ---------------------------------------------------------------------
// RFC 7540 §3.2 h2c Upgrade
// ---------------------------------------------------------------------

#[test]
fn h2c_upgrade_roundtrip_and_reuse() {
    let server = Server::bind_with_config(
        "127.0.0.1:0",
        ServerConfig {
            http2: true,
            event_driven: false,
            ..Default::default()
        },
    )
    .unwrap();
    let addr = server.local_addr().unwrap();
    let handle = server
        .serve_background(|req: courierust::http::request::Request<Body>| {
            let mut resp = courierust::http::response::Response::<Body>::with_status(200.into());
            resp.headers.insert(
                HeaderName::from_lowercase("x-method"),
                HeaderValue::from_bytes(req.method.as_str().as_bytes()).unwrap(),
            );
            let body = req.body.collect().unwrap();
            resp.body = Body::Bytes(body);
            resp
        })
        .unwrap();
    std::mem::forget(handle);

    let cfg = ClientConfig {
        http2: true,
        h2c_upgrade: true,
        connect_timeout: Some(Duration::from_secs(5)),
        read_timeout: Some(Duration::from_secs(5)),
        ..Default::default()
    };
    let client = Client::with_config(cfg);
    let base = format!("http://{addr}");

    // First request performs the Upgrade handshake and is answered on
    // the upgraded stream 1.
    let resp = client.get(&format!("{base}/upgrade")).unwrap();
    assert_eq!(resp.status.as_u16(), 200);
    assert_eq!(
        resp.headers.get("x-method").unwrap().to_str().unwrap(),
        "GET"
    );

    // Subsequent requests reuse the upgraded connection.
    let mut req = Request::new(Method::POST, "/echo");
    req.body = Body::Bytes(Bytes::from_static(b"after-upgrade"));
    let resp = client.execute(&format!("{base}/echo"), req).unwrap();
    assert_eq!(
        resp.body.collect().unwrap().to_str().unwrap(),
        "after-upgrade"
    );
}

#[test]
fn h2c_upgrade_declined_falls_back_to_h1() {
    // An h1-only server ignores `Upgrade: h2c` and answers normally; the
    // client must surface that HTTP/1.1 response.
    let server = Server::bind_with_config(
        "127.0.0.1:0",
        ServerConfig {
            http2: false,
            event_driven: false,
            ..Default::default()
        },
    )
    .unwrap();
    let addr = server.local_addr().unwrap();
    let handle = server
        .serve_background(|req: courierust::http::request::Request<Body>| {
            let mut resp = courierust::http::response::Response::<Body>::with_status(200.into());
            let body = req.body.collect().unwrap();
            resp.body = Body::Bytes(body);
            resp
        })
        .unwrap();
    std::mem::forget(handle);

    let cfg = ClientConfig {
        http2: true,
        h2c_upgrade: true,
        connect_timeout: Some(Duration::from_secs(5)),
        read_timeout: Some(Duration::from_secs(5)),
        ..Default::default()
    };
    let client = Client::with_config(cfg);
    let resp = client.get(&format!("http://{addr}/plain")).unwrap();
    assert_eq!(resp.status.as_u16(), 200);
    assert_eq!(resp.version, courierust::http::version::Version::HTTP_11);
}

// ---------------------------------------------------------------------
// Liveness: SETTINGS_TIMEOUT and keepalive dead-peer detection
// ---------------------------------------------------------------------

#[test]
fn h2_client_settings_timeout_drops_silent_peer() {
    // A raw server that accepts but never sends SETTINGS (so our
    // SETTINGS is never ACKed): the client must drop the connection
    // with SETTINGS_TIMEOUT.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        if let Ok((mut sock, _)) = listener.accept() {
            // Read whatever arrives, respond with nothing.
            let mut buf = [0u8; 4096];
            let _ = sock.set_read_timeout(Some(Duration::from_millis(300)));
            for _ in 0..60 {
                if sock.read(&mut buf).is_err() {
                    break;
                }
            }
        }
    });

    let cfg = ClientConfig {
        http2: true,
        connect_timeout: Some(Duration::from_secs(5)),
        read_timeout: Some(Duration::from_secs(5)),
        h2_settings_timeout: Some(Duration::from_millis(400)),
        h2_ping_interval: None,
        h2_ping_timeout: None,
        h2_idle_timeout: None,
        ..Default::default()
    };
    let client = Client::with_config(cfg);
    let started = std::time::Instant::now();
    let result = client.get(&format!("http://{addr}/"));
    assert!(
        result.is_err(),
        "request to a peer that never ACKs SETTINGS must fail"
    );
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "SETTINGS_TIMEOUT must fire promptly"
    );
}

#[test]
fn h2_client_keepalive_detects_dead_peer() {
    // A raw server that completes the SETTINGS exchange but then goes
    // silent: the client's keepalive PING must go unanswered and the
    // connection must be dropped (dead-peer detection).
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        if let Ok((sock, _)) = listener.accept() {
            sock.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
            let mut peer = RawH2Peer { stream: sock };
            assert!(peer.read_preface());
            let _ = peer.read_frame(); // client SETTINGS (after preface)
            peer.send_frame(0x4, 0, 0, &[]); // our SETTINGS (client ACKs it)
            // Stay open but never answer PINGs, so the client's keepalive
            // timeout (not an EOF) must be what fails the request.
            let mut buf = [0u8; 4096];
            let deadline = std::time::Instant::now() + Duration::from_secs(3);
            while std::time::Instant::now() < deadline {
                if peer.stream.read(&mut buf).is_err() {
                    break;
                }
            }
        }
    });

    let cfg = ClientConfig {
        http2: true,
        connect_timeout: Some(Duration::from_secs(5)),
        read_timeout: Some(Duration::from_secs(5)),
        h2_settings_timeout: Some(Duration::from_secs(5)),
        h2_ping_interval: Some(Duration::from_millis(200)),
        h2_ping_timeout: Some(Duration::from_millis(600)),
        h2_idle_timeout: None,
        ..Default::default()
    };
    let client = Client::with_config(cfg);
    let started = std::time::Instant::now();
    let result = client.get(&format!("http://{addr}/"));
    assert!(
        result.is_err(),
        "a peer that never responds to keepalive PINGs must be dropped"
    );
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "dead-peer detection must fire promptly"
    );
}
