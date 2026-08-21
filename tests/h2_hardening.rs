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
        if len > 0 && self.stream.read_exact(&mut payload).is_err() {
            return None;
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
        p == PREFACE
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
        threads: 1,
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
            threads: 1,
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
            threads: 1,
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
            sock.set_read_timeout(Some(Duration::from_millis(300)))
                .unwrap();
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

// ---------------------------------------------------------------------
// Content-Length / framing enforcement (RFC 9113 §8.1.2.6, §8.2.2)
// ---------------------------------------------------------------------

/// A literal-without-indexing HPACK field with a Huffman-encoded value
/// (used to inject malformed Huffman streams into a header block).
fn hpack_huff_value(name: &str, value_huff: &[u8]) -> Vec<u8> {
    let mut out = vec![0x00]; // literal without indexing, new name
    out.push(name.len() as u8);
    out.extend_from_slice(name.as_bytes());
    out.push(0x80 | (value_huff.len() as u8)); // Huffman flag
    out.extend_from_slice(value_huff);
    out
}

/// Read frames until an `RST_STREAM` on `stream_id`; returns the error
/// code (or `None` if the peer closes first).
fn wait_rst(peer: &mut RawH2Peer, stream_id: u32, timeout: Duration) -> Option<u32> {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        match peer.read_frame() {
            Some((0x3, _, sid, payload)) if sid == stream_id => {
                if payload.len() >= 4 {
                    return Some(u32::from_be_bytes([
                        payload[0], payload[1], payload[2], payload[3],
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

/// A standard GET request header block.
fn get_block() -> Vec<u8> {
    hpack(&[
        hdr(":method", "GET"),
        hdr(":path", "/"),
        hdr(":scheme", "http"),
    ])
}

#[test]
fn h2_rejects_conflicting_content_length() {
    // Two different content-length values are a request-smuggling vector
    // (CWE-444) and a connection error (RFC 9113 §8.1.2.6).
    let addr = spawn_h2_server(1 << 20);
    let mut peer = RawH2Peer::connect(addr).unwrap();
    peer.send_preface_and_settings();
    let block = hpack(&[
        hdr(":method", "POST"),
        hdr(":path", "/"),
        hdr(":scheme", "http"),
        hdr("content-length", "5"),
        hdr("content-length", "6"),
    ]);
    peer.send_frame(0x1, 0x4, 1, &block);
    let code = peer.wait_goaway(Duration::from_secs(5));
    assert_eq!(code, Some(0x1), "expected PROTOCOL_ERROR GOAWAY");
}

#[test]
fn h2_rejects_content_length_mismatch_stream_error() {
    // A request declaring content-length: 10 but sending only 5 bytes is
    // a STREAM error (RFC 9113 §5.4.2): the stream is reset with
    // PROTOCOL_ERROR, and the connection must stay usable.
    let addr = spawn_h2_server(1 << 20);
    let mut peer = RawH2Peer::connect(addr).unwrap();
    peer.send_preface_and_settings();
    let block = hpack(&[
        hdr(":method", "POST"),
        hdr(":path", "/"),
        hdr(":scheme", "http"),
        hdr("content-length", "10"),
    ]);
    peer.send_frame(0x1, 0x4, 1, &block); // HEADERS, no END_STREAM
    peer.send_frame(0x0, 0x1, 1, b"hello"); // 5 bytes + END_STREAM
    let rst = wait_rst(&mut peer, 1, Duration::from_secs(5));
    assert_eq!(rst, Some(0x1), "expected PROTOCOL_ERROR RST_STREAM");

    // The connection must still be usable: a fresh, valid request (with
    // END_STREAM on the HEADERS, since it has no body) is answered
    // normally.
    peer.send_frame(0x1, 0x5, 3, &get_block()); // END_HEADERS | END_STREAM
    let mut saw_response = false;
    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(5) {
        match peer.read_frame() {
            Some((0x1, _, 3, _)) => {
                saw_response = true;
                break;
            }
            Some((0x4, _, 0, _)) => continue, // SETTINGS ACK
            Some((0x0, _, 3, _)) => {
                saw_response = true;
                break;
            }
            Some(_) => continue,
            None => break,
        }
    }
    assert!(saw_response, "connection must survive a stream error");
}

#[test]
fn h2_rejects_transfer_encoding() {
    // transfer-encoding is forbidden in HTTP/2 (RFC 9113 §8.2.2); it is
    // an HTTP/1.1 hop-by-hop smuggling vector.
    let addr = spawn_h2_server(1 << 20);
    let mut peer = RawH2Peer::connect(addr).unwrap();
    peer.send_preface_and_settings();
    let block = hpack(&[
        hdr(":method", "GET"),
        hdr(":path", "/"),
        hdr(":scheme", "http"),
        hdr("transfer-encoding", "chunked"),
    ]);
    peer.send_frame(0x1, 0x4, 1, &block);
    let code = peer.wait_goaway(Duration::from_secs(5));
    assert_eq!(code, Some(0x1), "expected PROTOCOL_ERROR GOAWAY");
}

#[test]
fn h2_rejects_connection_specific_header() {
    // Connection-specific fields (RFC 9113 §8.2.2) must be rejected.
    let addr = spawn_h2_server(1 << 20);
    let mut peer = RawH2Peer::connect(addr).unwrap();
    peer.send_preface_and_settings();
    let block = hpack(&[
        hdr(":method", "GET"),
        hdr(":path", "/"),
        hdr(":scheme", "http"),
        hdr("connection", "keep-alive"),
    ]);
    peer.send_frame(0x1, 0x4, 1, &block);
    let code = peer.wait_goaway(Duration::from_secs(5));
    assert_eq!(code, Some(0x1), "expected PROTOCOL_ERROR GOAWAY");
}

#[test]
fn h2_rejects_te_with_non_trailers_value() {
    // `te` is only legal with the value `trailers` (RFC 9113 §8.2.2).
    let addr = spawn_h2_server(1 << 20);
    let mut peer = RawH2Peer::connect(addr).unwrap();
    peer.send_preface_and_settings();
    let block = hpack(&[
        hdr(":method", "GET"),
        hdr(":path", "/"),
        hdr(":scheme", "http"),
        hdr("te", "gzip"),
    ]);
    peer.send_frame(0x1, 0x4, 1, &block);
    let code = peer.wait_goaway(Duration::from_secs(5));
    assert_eq!(code, Some(0x1), "expected PROTOCOL_ERROR GOAWAY");
}

#[test]
fn h2_rejects_content_length_in_trailers() {
    // Framing fields must not appear in trailers (RFC 9113 §8.1).
    let addr = spawn_h2_server(1 << 20);
    let mut peer = RawH2Peer::connect(addr).unwrap();
    peer.send_preface_and_settings();
    // Valid request body, then trailers carrying content-length.
    let block = hpack(&[
        hdr(":method", "POST"),
        hdr(":path", "/"),
        hdr(":scheme", "http"),
    ]);
    peer.send_frame(0x1, 0x4, 1, &block); // HEADERS, no END_STREAM
    peer.send_frame(0x0, 0x0, 1, b"abc"); // DATA, no END_STREAM
    let trailer = hpack(&[hdr("content-length", "3")]);
    peer.send_frame(0x1, 0x4, 1, &trailer); // trailers + END_HEADERS
    let code = peer.wait_goaway(Duration::from_secs(5));
    assert_eq!(code, Some(0x1), "expected PROTOCOL_ERROR GOAWAY");
}

// ---------------------------------------------------------------------
// HPACK Huffman malformed streams
// ---------------------------------------------------------------------

#[test]
fn h2_rejects_truncated_huffman() {
    // A Huffman-encoded header value whose final code is cut short is a
    // COMPRESSION_ERROR (RFC 7541 §5.2).
    let addr = spawn_h2_server(1 << 20);
    let mut peer = RawH2Peer::connect(addr).unwrap();
    peer.send_preface_and_settings();
    let full = {
        let mut v = Vec::new();
        courierust::hpack::huffman::encode(b"hello", &mut v);
        v
    };
    assert!(full.len() > 2, "huffman('hello') must span >2 bytes");
    let mut block = get_block();
    block.extend_from_slice(&hpack_huff_value("x-huff", &full[..2]));
    peer.send_frame(0x1, 0x4, 1, &block);
    let code = peer.wait_goaway(Duration::from_secs(5));
    assert_eq!(code, Some(0x9), "expected COMPRESSION_ERROR GOAWAY");
}

#[test]
fn h2_rejects_huffman_eos() {
    // A Huffman stream containing the EOS symbol (30 ones) is invalid.
    let addr = spawn_h2_server(1 << 20);
    let mut peer = RawH2Peer::connect(addr).unwrap();
    peer.send_preface_and_settings();
    let mut block = get_block();
    block.extend_from_slice(&hpack_huff_value("x-huff", &[0xff, 0xff, 0xff, 0xff]));
    peer.send_frame(0x1, 0x4, 1, &block);
    let code = peer.wait_goaway(Duration::from_secs(5));
    assert_eq!(code, Some(0x9), "expected COMPRESSION_ERROR GOAWAY");
}

// ---------------------------------------------------------------------
// Flow control / SETTINGS
// ---------------------------------------------------------------------

#[test]
fn h2_rejects_window_update_overflow() {
    // A connection-level WINDOW_UPDATE that would push the window past
    // 2^31-1 is a FLOW_CONTROL_ERROR (RFC 9113 §6.9.1).
    let addr = spawn_h2_server(1 << 20);
    let mut peer = RawH2Peer::connect(addr).unwrap();
    peer.send_preface_and_settings();
    // 65535 (initial) + 0x7fffffff > 2^31 - 1.
    peer.send_frame(0x8, 0, 0, &0x7fff_ffffu32.to_be_bytes());
    let code = peer.wait_goaway(Duration::from_secs(5));
    assert_eq!(code, Some(0x3), "expected FLOW_CONTROL_ERROR GOAWAY");
}

#[test]
fn h2_rejects_data_exceeding_flow_window() {
    // Sending DATA beyond the advertised flow-control window is a
    // FLOW_CONTROL_ERROR (RFC 9113 §6.9). The server must not auto-release
    // receive credit here, otherwise the 5 × 16 KiB would legitimately be
    // granted and no violation would occur.
    let server = Server::bind_with_config(
        "127.0.0.1:0",
        ServerConfig {
            http2: true,
            event_driven: false,
            threads: 1,
            max_header_list: 1 << 20,
            auto_release_credit: false,
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

    let mut peer = RawH2Peer::connect(addr).unwrap();
    peer.send_preface_and_settings();
    peer.send_frame(0x1, 0x4, 1, &get_block()); // open stream 1
    let chunk = vec![b'x'; 16384];
    for _ in 0..5 {
        peer.send_frame(0x0, 0x0, 1, &chunk); // 5 × 16 KiB > 64 KiB conn window
    }
    let code = peer.wait_goaway(Duration::from_secs(5));
    assert_eq!(code, Some(0x3), "expected FLOW_CONTROL_ERROR GOAWAY");
}

#[test]
fn h2_rejects_settings_ack_with_payload() {
    // A SETTINGS ACK must have an empty payload (RFC 9113 §6.5.3).
    let addr = spawn_h2_server(1 << 20);
    let mut peer = RawH2Peer::connect(addr).unwrap();
    peer.send_preface_and_settings();
    peer.send_frame(0x4, 0x1, 0, &[0u8; 6]); // ACK flag + 6-byte payload
    let code = peer.wait_goaway(Duration::from_secs(5));
    assert_eq!(code, Some(0x6), "expected FRAME_SIZE_ERROR GOAWAY");
}

// ---------------------------------------------------------------------
// Concurrent stream limits
// ---------------------------------------------------------------------

#[test]
fn h2_rejects_excessive_concurrent_streams() {
    // A server advertising SETTINGS_MAX_CONCURRENT_STREAMS=2 must reset
    // the 3rd concurrent stream with REFUSED_STREAM (RFC 9113 §5.1.2).
    let server = Server::bind_with_config(
        "127.0.0.1:0",
        ServerConfig {
            http2: true,
            event_driven: false,
            threads: 1,
            h2_max_concurrent_streams: 2,
            ..Default::default()
        },
    )
    .unwrap();
    let addr = server.local_addr().unwrap();
    let handle = server
        .serve_background(|_req: courierust::http::request::Request<Body>| {
            // Never completes (no END_STREAM from the peer), so streams 1
            // and 3 stay open.
            let mut resp = courierust::http::response::Response::<Body>::with_status(200.into());
            resp.body = Body::Bytes(Bytes::from_static(b"ok"));
            resp
        })
        .unwrap();
    std::mem::forget(handle);

    let mut peer = RawH2Peer::connect(addr).unwrap();
    peer.send_preface_and_settings();
    // Two concurrent streams held open.
    peer.send_frame(0x1, 0x4, 1, &get_block());
    peer.send_frame(0x1, 0x4, 3, &get_block());
    // The third exceeds the limit.
    peer.send_frame(0x1, 0x4, 5, &get_block());
    let rst = wait_rst(&mut peer, 5, Duration::from_secs(5));
    assert_eq!(rst, Some(0x7), "expected REFUSED_STREAM RST_STREAM");
}

#[test]
fn h2_client_respects_peer_concurrent_stream_limit() {
    // The client must never exceed the peer's advertised
    // SETTINGS_MAX_CONCURRENT_STREAMS: excess requests wait for a free
    // stream slot instead of being opened on the connection.
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    let active = Arc::new(AtomicUsize::new(0));
    let max_seen = Arc::new(AtomicUsize::new(0));

    let server = Server::bind_with_config(
        "127.0.0.1:0",
        ServerConfig {
            http2: true,
            event_driven: false,
            threads: 1,
            h2_max_concurrent_streams: 2,
            ..Default::default()
        },
    )
    .unwrap();
    let addr = server.local_addr().unwrap();
    let active2 = active.clone();
    let max2 = max_seen.clone();
    let handle = server
        .serve_background(move |_req: courierust::http::request::Request<Body>| {
            let now = active2.fetch_add(1, Ordering::SeqCst) + 1;
            max2.fetch_max(now, Ordering::SeqCst);
            // Hold the stream open briefly so the client's deferral is
            // actually exercised (2 streams are in flight at any time).
            std::thread::sleep(Duration::from_millis(60));
            active2.fetch_sub(1, Ordering::SeqCst);
            let mut resp = courierust::http::response::Response::<Body>::with_status(200.into());
            resp.body = Body::Bytes(Bytes::from_static(b"ok"));
            resp
        })
        .unwrap();
    std::mem::forget(handle);

    let client = Client::with_config(ClientConfig {
        http2: true,
        max_connections_per_host: 1, // force all requests onto one connection
        connect_timeout: Some(Duration::from_secs(5)),
        read_timeout: Some(Duration::from_secs(10)),
        ..Default::default()
    });
    let base = format!("http://{addr}");
    let mut handles = Vec::new();
    for _ in 0..6 {
        let c = client.clone();
        let b = base.clone();
        handles.push(std::thread::spawn(move || {
            let req = courierust::http::request::Request::<Body>::new(Method::GET, "/bench");
            let resp = c.execute(&format!("{b}/bench"), req).unwrap();
            assert_eq!(resp.status.as_u16(), 200);
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    let seen = max_seen.load(Ordering::SeqCst);
    assert!(
        seen <= 2,
        "client exceeded the peer's concurrent-stream limit (max seen {seen})"
    );
}

// ---------------------------------------------------------------------
// Client-side content-length enforcement
// ---------------------------------------------------------------------

#[test]
fn h2_client_rejects_content_length_mismatch_response() {
    // A response declaring content-length: 100 but carrying only 2 bytes
    // must be surfaced as an error to the client.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        let (sock, _) = listener.accept().unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut peer = RawH2Peer { stream: sock };
        assert!(peer.read_preface());
        let _ = peer.read_frame(); // client SETTINGS
        peer.send_frame(0x4, 0, 0, &[]); // our SETTINGS
                                         // Wait for the request.
        loop {
            match peer.read_frame() {
                Some((0x1, _, 1, _)) => break,
                Some((0x4, _, 0, _)) => continue,
                Some(_) => continue,
                None => panic!("client closed before request"),
            }
        }
        // Response: content-length 100, body "hi" (2 bytes) + END_STREAM.
        let block = hpack(&[hdr(":status", "200"), hdr("content-length", "100")]);
        peer.send_frame(0x1, 0x4, 1, &block); // HEADERS, no END_STREAM
        peer.send_frame(0x0, 0x1, 1, b"hi"); // DATA + END_STREAM
                                             // Keep reading so the connection stays open long enough for the
                                             // client to observe the mismatch.
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
    // The mismatch is detected when the body ends, so it surfaces as a
    // body-read error even though the response head was already
    // delivered.
    if let Ok(resp) = result {
        let body_result = resp.body.collect();
        assert!(
            body_result.is_err(),
            "client must reject a response whose content-length does not match the body"
        );
    }
    // An `Err` surfaced at the head is also acceptable.
}
