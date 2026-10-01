//! WebSocket protocol conformance suite.
//!
//! This is the in-repo half of the external-correctness evidence: the
//! RFC 6455 / RFC 7692 rules that a peer can violate, driven over a real
//! socket against the real server, with the *mandated* outcome asserted
//! for each one. It is shaped like the Autobahn WebSocket test suite —
//! a table of frames in, an expected close code (or an expected reply)
//! out — so the same cases can be read side by side with an Autobahn
//! report; `scripts/autobahn_ws.ps1` runs the official suite itself.
//!
//! Why a table rather than a pile of `#[test]` functions: a conformance
//! suite is only as good as its coverage of the *categories* (framing,
//! payload, control, close handshake), and a table makes a missing
//! category visible. Every case runs even when an earlier one fails, so
//! one run reports every violation instead of the first.
//!
//! Only the blocking driver is used here. `tests/ws.rs` runs the shared
//! scenarios through both drivers; this file is about the wire rules,
//! which are driver-independent by construction (both drivers drive the
//! same `courierust_ws::Session`).

use courierust::courierust_body::Body;
use courierust::courierust_http::request::Request;
use courierust::courierust_http::response::Response;
use courierust::courierust_http::status::StatusCode;
use courierust::courierust_server::ws::{WsConfig, WsConn, WsData, WsService, WsUpgradeReply};
use courierust::courierust_server::{Handler, Server, ServerConfig};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug)]
enum FrameReadError {
    Io(std::io::Error),
    Invalid(String),
}

impl FrameReadError {
    fn is_disconnect(&self) -> bool {
        matches!(
            self,
            Self::Io(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::UnexpectedEof
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::BrokenPipe
                        | std::io::ErrorKind::NotConnected
                )
        )
    }
}

impl std::fmt::Display for FrameReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => error.fmt(f),
            Self::Invalid(message) => f.write_str(message),
        }
    }
}

// ---------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------

struct Echo;

impl WsService for Echo {
    fn on_message(&self, c: &mut WsConn, msg: WsData) {
        match msg {
            WsData::Text(t) => {
                let _ = c.send_text(&t);
            }
            WsData::Binary(b) => {
                let _ = c.send_binary(&b);
            }
        }
    }
}

struct EchoHandler;

impl Handler for EchoHandler {
    fn handle(&self, _req: Request<Body>) -> Response<Body> {
        Response::with_status(StatusCode::from_u16(404))
    }

    fn websocket(&self, _req: &Request<Body>) -> WsUpgradeReply {
        WsUpgradeReply::Accept(Arc::new(Echo))
    }
}

fn spawn_server(max_message: usize) -> SocketAddr {
    let server = Server::bind_with_config(
        "127.0.0.1:0",
        ServerConfig {
            event_driven: false,
            threads: 4,
            websocket: WsConfig {
                max_message,
                max_frame: max_message,
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .expect("bind");
    let addr = server.local_addr().expect("addr");
    std::mem::forget(server.serve_background(EchoHandler).expect("serve"));
    addr
}

/// Perform the opening handshake by hand and return the socket.
fn handshake(addr: SocketAddr, path: &str) -> TcpStream {
    let mut sock = TcpStream::connect(addr).expect("connect");
    sock.set_nodelay(true).ok();
    sock.set_read_timeout(Some(Duration::from_secs(5))).ok();
    sock.set_write_timeout(Some(Duration::from_secs(5))).ok();
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {addr}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    sock.write_all(request.as_bytes()).expect("write handshake");
    sock.flush().ok();
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        let n = sock.read(&mut byte).expect("read response head");
        assert_ne!(n, 0, "the server closed during the handshake");
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

/// A client-to-server frame with the mask bit set, as `tungstenite`,
/// Autobahn and every browser send it. `key` is fixed so a failure is
/// reproducible.
fn masked(opcode: u8, payload: &[u8], fin: bool) -> Vec<u8> {
    masked_with(opcode, payload, fin, [0x21, 0x22, 0x23, 0x24], None)
}

/// The same, with an explicit masking key and an optional length-encoding
/// override (`Some(126)` forces the 16-bit form, `Some(127)` the 64-bit
/// one) so the non-minimal encodings can be produced deliberately.
fn masked_with(
    opcode: u8,
    payload: &[u8],
    fin: bool,
    key: [u8; 4],
    force_len: Option<u8>,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(if fin { 0x80 | opcode } else { opcode });
    let len = payload.len();
    match force_len {
        Some(126) => {
            out.push(0x80 | 126);
            out.extend_from_slice(&(len as u16).to_be_bytes());
        }
        Some(127) => {
            out.push(0x80 | 127);
            out.extend_from_slice(&(len as u64).to_be_bytes());
        }
        _ if len < 126 => out.push(0x80 | len as u8),
        _ if len <= u16::MAX as usize => {
            out.push(0x80 | 126);
            out.extend_from_slice(&(len as u16).to_be_bytes());
        }
        _ => {
            out.push(0x80 | 127);
            out.extend_from_slice(&(len as u64).to_be_bytes());
        }
    }
    out.extend_from_slice(&key);
    let mut body = payload.to_vec();
    mask_in_place(&mut body, key);
    out.extend_from_slice(&body);
    out
}

fn frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
    masked(opcode, payload, true)
}

fn close_payload(code: u16, reason: &str) -> Vec<u8> {
    let mut out = code.to_be_bytes().to_vec();
    out.extend_from_slice(reason.as_bytes());
    out
}

/// Read one server-to-client frame. Returns `Err` instead of panicking so
/// a failing case reports *why* rather than aborting the run.
fn read_frame(sock: &mut TcpStream) -> Result<(u8, Vec<u8>), FrameReadError> {
    let mut head = [0u8; 2];
    sock.read_exact(&mut head).map_err(FrameReadError::Io)?;
    let opcode = head[0] & 0x0f;
    if head[1] & 0x80 != 0 {
        return Err(FrameReadError::Invalid("a server frame was masked".into()));
    }
    let len = match head[1] & 0x7f {
        126 => {
            let mut b = [0u8; 2];
            sock.read_exact(&mut b).map_err(FrameReadError::Io)?;
            u16::from_be_bytes(b) as usize
        }
        127 => {
            let mut b = [0u8; 8];
            sock.read_exact(&mut b).map_err(FrameReadError::Io)?;
            let n = u64::from_be_bytes(b);
            if n > 8 * 1024 * 1024 {
                return Err(FrameReadError::Invalid(format!(
                    "absurd payload length {n}"
                )));
            }
            n as usize
        }
        n => n as usize,
    };
    let mut payload = vec![0u8; len];
    sock.read_exact(&mut payload).map_err(FrameReadError::Io)?;
    Ok((opcode, payload))
}

/// Read frames until one satisfies `wanted`, tolerating interleaved
/// Ping/Pong traffic (which a conformant server may send at any time).
fn read_until(
    sock: &mut TcpStream,
    wanted: impl Fn(u8) -> bool,
    what: &str,
) -> Result<(u8, Vec<u8>), FrameReadError> {
    for _ in 0..8 {
        let (opcode, payload) = read_frame(sock)?;
        if wanted(opcode) {
            return Ok((opcode, payload));
        }
        if !matches!(opcode, 0x9 | 0xA) {
            return Err(FrameReadError::Invalid(format!(
                "unexpected opcode 0x{opcode:x} while waiting for {what}"
            )));
        }
    }
    Err(FrameReadError::Invalid(format!(
        "no {what} within 8 frames"
    )))
}

#[test]
fn read_until_rejects_unexpected_data_frames() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let mut client = TcpStream::connect(addr).unwrap();
    let (mut peer, _) = listener.accept().unwrap();
    client
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    peer.write_all(&[0x81, 1, b'x']).unwrap();

    let error = read_until(&mut client, |opcode| opcode == 0x8, "close")
        .expect_err("a text data frame is not ignorable while waiting for Close");
    assert!(
        matches!(error, FrameReadError::Invalid(ref message) if message.contains("unexpected opcode")),
        "expected an unexpected-frame error, got {error}"
    );
}

// ---------------------------------------------------------------------
// The case table
// ---------------------------------------------------------------------

/// What the server must do with the frames it was sent.
enum Expect {
    /// Answer with a Close frame carrying this code (RFC 6455 §7.4).
    Close(u16),
    /// The connection must fail with this code, but the RFC allows failing it outright
    CloseOrDisconnect(u16),
    /// Echo this text back in one frame.
    Text(String),
    /// Echo this binary payload back in one frame.
    Binary(Vec<u8>),
    /// Answer with a Pong carrying exactly this payload (§5.5.3).
    Pong(Vec<u8>),
    /// The frames must not end the connection
    Alive,
}

struct Case {
    name: &'static str,
    frames: Vec<Vec<u8>>,
    expect: Expect,
}

impl Case {
    fn new(name: &'static str, frames: Vec<Vec<u8>>, expect: Expect) -> Self {
        Self {
            name,
            frames,
            expect,
        }
    }
}

fn run(case: &Case, max_message: usize) -> Result<(), String> {
    let addr = spawn_server(max_message);
    let mut sock = handshake(addr, "/echo");
    for f in &case.frames {
        sock.write_all(f).map_err(|e| format!("write: {e}"))?;
    }
    sock.flush().map_err(|e| e.to_string())?;

    match &case.expect {
        Expect::Close(code) => {
            let (opcode, payload) =
                read_until(&mut sock, |op| op == 0x8, "close").map_err(|e| e.to_string())?;
            debug_assert_eq!(opcode, 0x8);
            if payload.len() < 2 {
                return Err(format!("expected close {code}, got an empty close"));
            }
            let got = u16::from_be_bytes([payload[0], payload[1]]);
            if got != *code {
                return Err(format!("expected close {code}, got {got}"));
            }
            Ok(())
        }
        Expect::CloseOrDisconnect(code) => match read_until(&mut sock, |op| op == 0x8, "close") {
            Ok((_, payload)) if payload.len() >= 2 => {
                let got = u16::from_be_bytes([payload[0], payload[1]]);
                if got != *code {
                    return Err(format!("expected close {code}, got {got}"));
                }
                Ok(())
            }
            Ok(_) => Err(format!("expected close {code}, got an empty close")),
            Err(error) if error.is_disconnect() => Ok(()),
            Err(error) => Err(format!("expected close or disconnect, got {error}")),
        },
        Expect::Text(want) => {
            let (_, payload) =
                read_until(&mut sock, |op| op == 0x1, "text echo").map_err(|e| e.to_string())?;
            if payload != want.as_bytes() {
                return Err(format!(
                    "echo mismatch: wanted {want:?}, got {:?}",
                    String::from_utf8_lossy(&payload)
                ));
            }
            Ok(())
        }
        Expect::Binary(want) => {
            let (_, payload) =
                read_until(&mut sock, |op| op == 0x2, "binary echo").map_err(|e| e.to_string())?;
            if &payload != want {
                return Err(format!(
                    "echo mismatch: wanted {} bytes, got {}",
                    want.len(),
                    payload.len()
                ));
            }
            Ok(())
        }
        Expect::Pong(want) => {
            let (_, payload) =
                read_until(&mut sock, |op| op == 0xA, "pong").map_err(|e| e.to_string())?;
            if &payload != want {
                return Err(format!(
                    "pong mismatch: wanted {} bytes, got {}",
                    want.len(),
                    payload.len()
                ));
            }
            Ok(())
        }
        Expect::Alive => {
            let follow_up = frame(0x1, b"still alive");
            sock.write_all(&follow_up).map_err(|e| e.to_string())?;
            sock.flush().ok();
            let (_, payload) =
                read_until(&mut sock, |op| op == 0x1, "text echo").map_err(|e| e.to_string())?;
            if payload != b"still alive" {
                return Err(format!(
                    "the connection did not survive: got {:?}",
                    String::from_utf8_lossy(&payload)
                ));
            }
            Ok(())
        }
    }
}

#[test]
fn close_or_disconnect_does_not_accept_timeouts_or_protocol_errors() {
    assert!(
        FrameReadError::Io(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)).is_disconnect()
    );
    assert!(
        !FrameReadError::Io(std::io::Error::from(std::io::ErrorKind::TimedOut)).is_disconnect()
    );
    assert!(!FrameReadError::Invalid("no close within 8 frames".into()).is_disconnect());
}

/// Run every case and report all failures, not just the first.
fn check(cases: &[Case], max_message: usize) {
    let mut failures = Vec::new();
    for case in cases {
        if let Err(e) = run(case, max_message) {
            failures.push(format!("  {}: {e}", case.name));
        }
    }
    if !failures.is_empty() {
        panic!(
            "{} of {} conformance cases failed:\n{}",
            failures.len(),
            cases.len(),
            failures.join("\n")
        );
    }
}

// ---------------------------------------------------------------------
// Framing (§5.2): the length forms, and the encodings a proxy would read
// differently from us
// ---------------------------------------------------------------------

#[test]
fn framing_rules() {
    let text_125 = "x".repeat(125);
    let bin_126 = vec![b'y'; 126];
    let bin_65535 = vec![b'z'; 65_535];
    let bin_70000 = vec![0x5au8; 70_000];
    let cases = vec![
        Case::new(
            "zero-length text",
            vec![frame(0x1, b"")],
            Expect::Text(String::new()),
        ),
        Case::new(
            "125-byte text (last 7-bit length)",
            vec![frame(0x1, text_125.as_bytes())],
            Expect::Text(text_125.clone()),
        ),
        Case::new(
            "126-byte binary (first 16-bit length)",
            vec![frame(0x2, &bin_126)],
            Expect::Binary(bin_126.clone()),
        ),
        Case::new(
            "65535-byte binary (last 16-bit length)",
            vec![frame(0x2, &bin_65535)],
            Expect::Binary(bin_65535.clone()),
        ),
        Case::new(
            "70000-byte binary (64-bit length)",
            vec![frame(0x2, &bin_70000)],
            Expect::Binary(bin_70000.clone()),
        ),
        Case::new(
            "non-minimal 16-bit length for 5 bytes",
            vec![masked_with(0x1, b"hello", true, [1, 2, 3, 4], Some(126))],
            Expect::Close(1002),
        ),
        Case::new(
            "non-minimal 64-bit length for 5 bytes",
            vec![masked_with(0x1, b"hello", true, [1, 2, 3, 4], Some(127))],
            Expect::Close(1002),
        ),
        Case::new(
            "64-bit length with the high bit set",
            {
                let mut f = vec![0x81u8, 0x80 | 127];
                f.extend_from_slice(&0x8000_0000_0000_0005u64.to_be_bytes());
                f.extend_from_slice(&[1, 2, 3, 4]);
                vec![f]
            },
            Expect::Close(1002),
        ),
        Case::new(
            "reserved opcode 0x3",
            vec![frame(0x3, b"x")],
            Expect::Close(1002),
        ),
        Case::new(
            "reserved opcode 0xB",
            vec![frame(0xB, b"x")],
            Expect::Close(1002),
        ),
        Case::new(
            "unmasked client frame (§5.1)",
            {
                let mut f = vec![0x81u8, 5];
                f.extend_from_slice(b"cheeky");
                vec![f]
            },
            Expect::Close(1002),
        ),
        Case::new(
            "RSV1 set without a negotiated extension",
            {
                let mut f = frame(0x1, b"x");
                f[0] |= 0x40;
                vec![f]
            },
            Expect::Close(1002),
        ),
        Case::new(
            "RSV2 set without a negotiated extension",
            {
                let mut f = frame(0x1, b"x");
                f[0] |= 0x20;
                vec![f]
            },
            Expect::Close(1002),
        ),
        Case::new(
            "RSV3 set without a negotiated extension",
            {
                let mut f = frame(0x1, b"x");
                f[0] |= 0x10;
                vec![f]
            },
            Expect::Close(1002),
        ),
    ];
    check(&cases, 1 << 20);
}

// ---------------------------------------------------------------------
// Fragmentation (§5.4): reassembly, and the sequences that have no
// meaning
// ---------------------------------------------------------------------

#[test]
fn fragmentation_rules() {
    let cases = vec![
        Case::new(
            "three-fragment text",
            vec![
                masked(0x1, b"frag", false),
                masked(0x0, b"ment", false),
                masked(0x0, b"ed", true),
            ],
            Expect::Text(String::from("fragmented")),
        ),
        Case::new(
            "fragments with an interleaved ping",
            vec![
                masked(0x1, b"frag", false),
                masked(0x9, b"ping", true),
                masked(0x0, b"mented", true),
            ],
            Expect::Text(String::from("fragmented")),
        ),
        Case::new(
            "a UTF-8 character split across fragments",
            {
                let text = "日本語".as_bytes();
                vec![
                    masked(0x1, &text[..1], false),
                    masked(0x0, &text[1..4], false),
                    masked(0x0, &text[4..], true),
                ]
            },
            Expect::Text(String::from("日本語")),
        ),
        Case::new(
            "continuation without a started message",
            vec![masked(0x0, b"orphan", true)],
            Expect::Close(1002),
        ),
        Case::new(
            "a new data frame while a fragmented message is open",
            vec![masked(0x1, b"first", false), masked(0x1, b"second", true)],
            Expect::Close(1002),
        ),
    ];
    check(&cases, 1 << 20);
}

// ---------------------------------------------------------------------
// Control frames (§5.5): never fragmented, never longer than 125 bytes,
// and the Pong payload must be identical
// ---------------------------------------------------------------------

#[test]
fn control_frame_rules() {
    let cases = vec![
        Case::new(
            "ping with a payload is answered with the same payload",
            vec![frame(0x9, b"are you there")],
            Expect::Pong(b"are you there".to_vec()),
        ),
        Case::new(
            "ping with no payload",
            vec![frame(0x9, b"")],
            Expect::Pong(Vec::new()),
        ),
        Case::new(
            "ping with the maximum 125-byte payload",
            vec![frame(0x9, &[0x41u8; 125])],
            Expect::Pong(vec![0x41u8; 125]),
        ),
        Case::new(
            "fragmented ping (FIN clear on a control frame)",
            vec![masked(0x9, b"x", false)],
            Expect::Close(1002),
        ),
        Case::new(
            "fragmented pong (FIN clear on a control frame)",
            vec![masked(0xA, b"x", false)],
            Expect::Close(1002),
        ),
        Case::new(
            "ping longer than 125 bytes",
            vec![frame(0x9, &[0u8; 126])],
            Expect::Close(1002),
        ),
        Case::new(
            "an unsolicited pong is ignored, not fatal",
            vec![frame(0xA, b"unsolicited")],
            Expect::Alive,
        ),
    ];
    check(&cases, 1 << 20);
}

// ---------------------------------------------------------------------
// Payload (§8.1) and size limits (§7.4.1)
// ---------------------------------------------------------------------

#[test]
fn payload_and_limit_rules() {
    let cases = vec![
        Case::new(
            "invalid UTF-8 in a text frame",
            vec![frame(0x1, &[0x41, 0xff, 0x42])],
            Expect::Close(1007),
        ),
        Case::new(
            "a truncated sequence at the end of a text message",
            vec![frame(0x1, &[0x41, 0xE6, 0x97])],
            Expect::Close(1007),
        ),
        Case::new(
            "a surrogate half encoded in UTF-8",
            vec![frame(0x1, &[0xED, 0xA0, 0x80])],
            Expect::Close(1007),
        ),
        Case::new(
            "an overlong encoding",
            vec![frame(0x1, &[0xC0, 0xAF])],
            Expect::Close(1007),
        ),
        Case::new(
            "invalid UTF-8 arriving in a continuation fragment",
            vec![masked(0x1, b"AB", false), masked(0x0, &[0xFF], true)],
            Expect::Close(1007),
        ),
        Case::new(
            "arbitrary bytes in a binary frame are not validated",
            vec![frame(0x2, &[0xff, 0x00, 0xfe])],
            Expect::Binary(vec![0xff, 0x00, 0xfe]),
        ),
        // Against a 4 KiB `max_message`: the server must refuse before it
        // buffers the payload, with 1009 rather than by closing silently.
        Case::new(
            "a text message over the message limit",
            vec![frame(0x1, &[0x41u8; 8192])],
            Expect::CloseOrDisconnect(1009),
        ),
        Case::new(
            "a message over the limit assembled from fragments",
            vec![
                masked(0x1, &[0x41u8; 3000], false),
                masked(0x0, &[0x41u8; 3000], false),
                masked(0x0, &[0x41u8; 3000], true),
            ],
            Expect::CloseOrDisconnect(1009),
        ),
    ];
    check(&cases, 4096);
}

// ---------------------------------------------------------------------
// The closing handshake (§5.5.1, §7.4): the codes that may appear on the
// wire, and the ones that must never
// ---------------------------------------------------------------------

#[test]
fn close_handshake_rules() {
    let cases = vec![
        Case::new(
            "close 1000 with a reason is echoed as 1000",
            vec![frame(0x8, &close_payload(1000, "bye"))],
            Expect::Close(1000),
        ),
        Case::new(
            "close with no payload is answered with 1000",
            vec![frame(0x8, b"")],
            Expect::Close(1000),
        ),
        Case::new(
            "close 1001 (going away)",
            vec![frame(0x8, &close_payload(1001, ""))],
            Expect::Close(1001),
        ),
        Case::new(
            "close 3000 (registered application code)",
            vec![frame(0x8, &close_payload(3000, ""))],
            Expect::Close(3000),
        ),
        Case::new(
            "close 4999 (last legal registered code)",
            vec![frame(0x8, &close_payload(4999, ""))],
            Expect::Close(4999),
        ),
        Case::new(
            "a one-byte close payload is malformed",
            vec![frame(0x8, &[0x03])],
            Expect::Close(1002),
        ),
        Case::new(
            "close 1005 must not appear on the wire (§7.4.1)",
            vec![frame(0x8, &close_payload(1005, ""))],
            Expect::Close(1002),
        ),
        Case::new(
            "close 1006 must not appear on the wire",
            vec![frame(0x8, &close_payload(1006, ""))],
            Expect::Close(1002),
        ),
        Case::new(
            "close 999 is outside every legal range",
            vec![frame(0x8, &close_payload(999, ""))],
            Expect::Close(1002),
        ),
        Case::new(
            "close 5000 is outside every legal range",
            vec![frame(0x8, &close_payload(5000, ""))],
            Expect::Close(1002),
        ),
        Case::new(
            "close 1016 is not a registered code",
            vec![frame(0x8, &close_payload(1016, ""))],
            Expect::Close(1002),
        ),
        Case::new(
            "a close reason that is not UTF-8",
            vec![frame(0x8, &[0x03, 0xE8, 0xFF])],
            Expect::Close(1007),
        ),
        Case::new(
            "a fragmented close frame",
            vec![masked(0x8, b"x", false)],
            Expect::Close(1002),
        ),
    ];
    check(&cases, 1 << 20);
}
