//! WebSocket benchmark: courierust vs tungstenite vs tokio-tungstenite.
//!
//! Two layers are measured, because they answer different questions:
//!
//! 1. **Codec layer** (no sockets): frame encode, frame decode, payload
//!    masking, UTF-8 validation. This isolates the per-byte work from
//!    scheduler and syscall noise, and it is where the two
//!    implementations differ most.
//! 2. **Echo loop over loopback TCP**: N request/response messages of a
//!    given size, measured as messages/second and MiB/second. This is the
//!    number an application actually feels. Both a *blocking* peer
//!    (tungstenite, which is what our blocking driver is comparable to)
//!    and an *async* peer (tokio-tungstenite) are measured.
//!
//! Run with:
//! ```text
//! cargo bench --manifest-path benches/Cargo.toml --bench ws
//! ```
//!
//! Methodology notes (kept in the output so a reader can judge the
//! numbers): loopback TCP with `TCP_NODELAY`, single producer/consumer
//! thread, warmup rounds discarded, median of the reported repetitions,
//! identical payloads for every implementation, and the same machine,
//! same process, same build profile.

use courierust::courierust_body::Body;
use courierust::courierust_client::ws::WebSocket as CourierustWs;
use courierust::courierust_client::ClientConfig;
use courierust::courierust_http::request::Request;
use courierust::courierust_http::response::Response;
use courierust::courierust_server::ws::{WsConn, WsData, WsService, WsUpgradeReply};
use courierust::courierust_server::{Handler, Server, ServerConfig};
use courierust::courierust_ws::frame::MAX_HEADER_LEN;
use courierust::courierust_ws::frame::{FrameHeader as WsHeader, Mask};
use courierust::courierust_ws::writer::{FrameWriter, VecSink};
use courierust::courierust_ws::{FrameSink, MaskSource, OpCode, Utf8Validator};
use futures_util::{SinkExt, StreamExt};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tungstenite::Message as TungMessage;

// ---------------------------------------------------------------------
// Timing helpers
// ---------------------------------------------------------------------

/// Median nanoseconds per operation.
///
/// Each sample runs `iters` operations, because `Instant::now()` on
/// Windows has ~100 ns granularity: timing a single 64-byte frame
/// against that clock measures the clock, not the code.
fn median_ns(runs: usize, iters: usize, mut f: impl FnMut()) -> f64 {
    let mut samples = Vec::with_capacity(runs);
    for _ in 0..runs {
        let start = Instant::now();
        for _ in 0..iters {
            f();
        }
        samples.push(start.elapsed().as_secs_f64() / iters as f64);
    }
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    samples[samples.len() / 2] * 1e9
}

/// Iterations per sample for a payload of `size` bytes: enough work to
/// clear the clock resolution without taking seconds per sample.
fn iters_for(size: usize) -> usize {
    match size {
        0..=128 => 4_000,
        129..=4096 => 2_000,
        4097..=65_536 => 200,
        _ => 20,
    }
}

fn mib_per_sec(bytes: usize, seconds: f64) -> f64 {
    (bytes as f64 / (1024.0 * 1024.0)) / seconds
}

fn print_row(label: &str, ns: f64, bytes: usize) {
    println!(
        "  {label:<34} {:>10.1} ns/op   {:>10.1} MiB/s",
        ns,
        mib_per_sec(bytes, ns / 1e9)
    );
}

// ---------------------------------------------------------------------
// Codec layer
// ---------------------------------------------------------------------

fn codec_benchmarks() {
    println!("\n== codec layer (no sockets) ==\n");
    let sizes = [64usize, 1024, 16 * 1024, 256 * 1024];

    for &size in &sizes {
        let payload = vec![0x5au8; size];
        let iters = iters_for(size);
        println!("payload {size} bytes ({iters} ops/sample)");

        // --- frame encode, server role (unmasked) -------------------
        let mut server_sink = VecSink::new();
        let ours = median_ns(15, iters, || {
            let mut head = [0u8; MAX_HEADER_LEN];
            let header = WsHeader::data(OpCode::Binary, true, payload.len() as u64);
            let n = header.write(&mut head);
            server_sink.bytes.clear();
            server_sink.write_frame(&head[..n], &payload, None).unwrap();
        });
        print_row("courierust encode (unmasked)", ours, size);

        // Fairness: the frame is built once and cloned inside the loop
        // (`Frame` holds a `Bytes`, so the clone is a refcount bump), and
        // the output buffer is reused. That leaves only the encode work
        // being measured — same as our row above.
        let theirs_frame = tungstenite::protocol::frame::Frame::message(
            payload.clone(),
            tungstenite::protocol::frame::coding::OpCode::Data(
                tungstenite::protocol::frame::coding::Data::Binary,
            ),
            true,
        );
        let mut theirs_out = Vec::with_capacity(size + MAX_HEADER_LEN);
        let theirs = median_ns(15, iters, || {
            theirs_out.clear();
            let _ = theirs_frame.clone().format(&mut theirs_out);
        });
        print_row("tungstenite encode (unmasked)", theirs, size);

        // --- frame encode, client role (masked) ---------------------
        let mut client_writer = FrameWriter::new(
            VecSink::new(),
            MaskSource::Fixed([1, 2, 3, 4]),
            None,
        );
        let ours_masked = median_ns(15, iters, || {
            client_writer.sink_mut().bytes.clear();
            client_writer.write_frame(OpCode::Binary, &payload, true, false).ok();
        });
        print_row("courierust encode (masked)", ours_masked, size);

        // Same fairness rule, but note that tungstenite's masked path
        // allocates a fresh payload copy per frame (its `format` takes the
        // payload out of the frame and masks a copy). That is its public
        // behaviour, so it is what the row reports.
        let mut theirs_masked_frame = theirs_frame.clone();
        theirs_masked_frame.header_mut().mask = Some([1, 2, 3, 4]);
        let theirs_masked = median_ns(15, iters, || {
            theirs_out.clear();
            let _ = theirs_masked_frame.clone().format(&mut theirs_out);
        });
        print_row("tungstenite encode (masked)", theirs_masked, size);

        // --- masking alone ------------------------------------------
        // tungstenite's masking entry point is private in 0.30, so the
        // public masked-encode path above is the comparable measurement.
        let mask = Mask::new([1, 2, 3, 4]);
        let mut buf = payload.clone();
        let ours_mask = median_ns(15, iters, || {
            mask.apply(0, &mut buf);
        });
        print_row("courierust mask (in place)", ours_mask, size);

        // --- frame decode: header + unmask --------------------------
        let wire = {
            let mut w = vec![0u8; MAX_HEADER_LEN];
            let header = WsHeader {
                fin: true,
                rsv1: false,
                rsv2: false,
                rsv3: false,
                opcode: OpCode::Binary,
                masked: true,
                mask_key: [1, 2, 3, 4],
                payload_len: size as u64,
                header_len: 0,
            };
            let n = header.write(&mut w);
            w.truncate(n);
            let mut body = payload.clone();
            Mask::new([1, 2, 3, 4]).apply(0, &mut body);
            w.extend_from_slice(&body);
            w
        };
        let mut scratch = payload.clone();
        let ours_decode = median_ns(15, iters, || {
            let header = WsHeader::parse(&wire).unwrap().unwrap();
            let body = &wire[header.header_len..];
            scratch.copy_from_slice(body);
            Mask::new(header.mask_key).apply(0, &mut scratch);
        });
        print_row("courierust decode + unmask", ours_decode, size);

        // tungstenite 0.30 does not expose in-place unmasking publicly,
        // so this row measures its header parse plus the payload copy the
        // caller has to make. Its masking cost is measured by the masked
        // encode rows above, which go through the same private transform.
        let theirs_wire = wire.clone();
        let theirs_decode = median_ns(15, iters, || {
            let mut cursor = std::io::Cursor::new(&theirs_wire);
            let (_header, len) = tungstenite::protocol::frame::FrameHeader::parse(&mut cursor)
                .unwrap()
                .unwrap();
            let start = cursor.position() as usize;
            let body = &theirs_wire[start..start + len as usize];
            std::hint::black_box(body);
        });
        print_row("tungstenite parse header", theirs_decode, size);
        println!();
    }

    // --- UTF-8 validation over a realistic text block ---------------
    let text = "The quick brown fox jumps over the lazy dog. 日本語テキスト 🦀 "
        .repeat(64);
    let bytes = text.as_bytes();
    let ours = median_ns(15, 2000, || {
        let mut v = Utf8Validator::new();
        v.feed(bytes).unwrap();
    });
    print_row("courierust utf8 validate", ours, bytes.len());
    let theirs = median_ns(15, 2000, || {
        std::str::from_utf8(bytes).unwrap();
    });
    print_row("std str::from_utf8", theirs, bytes.len());
}

// ---------------------------------------------------------------------
// Echo loop: courierust (blocking driver)
// ---------------------------------------------------------------------

struct EchoHandler;
struct EchoService;

impl WsService for EchoService {
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

impl Handler for EchoHandler {
    fn handle(&self, _req: Request<Body>) -> Response<Body> {
        Response::with_status(courierust::courierust_http::status::StatusCode::from_u16(404))
    }

    fn websocket(&self, _req: &Request<Body>) -> WsUpgradeReply {
        WsUpgradeReply::Accept(Arc::new(EchoService))
    }
}

/// Start our echo server; returns its address.
///
/// Compression is **off** by default here on purpose: tungstenite is
/// built below without its `deflate` feature, so a compressed comparison
/// would not be like for like. The compression-on rows are reported
/// separately further down.
fn start_courierust_server() -> std::net::SocketAddr {
    start_courierust_server_with(true, false)
}

/// Start our echo server with or without socket-level timeouts, so the
/// benchmark can show what a keepalive/liveness timeout costs.
fn start_courierust_server_with(timeouts: bool, compression: bool) -> std::net::SocketAddr {
    start_courierust_server_tuned(timeouts, compression, 64 * 1024)
}

fn start_courierust_server_tuned(
    timeouts: bool,
    compression: bool,
    read_buffer: usize,
) -> std::net::SocketAddr {
    let config = ServerConfig {
        // The blocking driver: one worker per WebSocket, which is the
        // comparable shape to a synchronous tungstenite peer.
        event_driven: false,
        threads: 2,
        read_timeout: if timeouts {
            Some(Duration::from_secs(120))
        } else {
            None
        },
        websocket: courierust::courierust_server::ws::WsConfig {
            ping_interval: if timeouts {
                Some(Duration::from_secs(30))
            } else {
                None
            },
            compression: courierust::courierust_ws::PmDeflatePolicy {
                enabled: compression,
                ..Default::default()
            },
            read_buffer,
            ..Default::default()
        },
        ..Default::default()
    };
    let server = Server::bind_with_config("127.0.0.1:0", config).unwrap();
    let addr = server.local_addr().unwrap();
    std::mem::forget(server.serve_background(EchoHandler).unwrap());
    addr
}

fn echo_courierust(addr: std::net::SocketAddr, size: usize, count: usize) -> f64 {
    echo_courierust_with(addr, size, count, true, false)
}

fn echo_courierust_with(
    addr: std::net::SocketAddr,
    size: usize,
    count: usize,
    read_timeout: bool,
    compression: bool,
) -> f64 {
    echo_courierust_tuned(addr, size, count, read_timeout, compression, 64 * 1024)
}

/// The same echo with an explicit read-buffer size, so the benchmark can
/// separate "how much work the codec does" from "how many bytes each
/// transport read carries".
fn echo_courierust_tuned(
    addr: std::net::SocketAddr,
    size: usize,
    count: usize,
    read_timeout: bool,
    compression: bool,
    read_buffer: usize,
) -> f64 {
    let mut ws = CourierustWs::connect_with(
        &format!("ws://{addr}/echo"),
        &ClientConfig {
            read_timeout: if read_timeout {
                Some(Duration::from_secs(30))
            } else {
                None
            },
            ..Default::default()
        },
        &courierust::courierust_client::ws::WsClientOptions {
            compression,
            read_buffer,
            ..Default::default()
        },
    )
    .expect("connect");
    let payload = vec![0x5au8; size];
    let start = Instant::now();
    for _ in 0..count {
        ws.send_binary(&payload).unwrap();
        let event = ws.read_message().unwrap();
        match event {
            courierust::courierust_ws::Event::Binary(b) => assert_eq!(b.len(), size),
            other => panic!("unexpected {other:?}"),
        }
    }
    start.elapsed().as_secs_f64()
}

/// Our client against tungstenite's server: isolates the client half.
fn echo_courierust_client_on_tungstenite_server(
    addr: std::net::SocketAddr,
    size: usize,
    count: usize,
) -> f64 {
    let mut ws = CourierustWs::connect(
        &format!("ws://{addr}/echo"),
        &ClientConfig {
            read_timeout: Some(Duration::from_secs(30)),
            ..Default::default()
        },
    )
    .expect("connect");
    let payload = vec![0x5au8; size];
    let start = Instant::now();
    for _ in 0..count {
        ws.send_binary(&payload).unwrap();
        match ws.read_message().unwrap() {
            courierust::courierust_ws::Event::Binary(b) => assert_eq!(b.len(), size),
            other => panic!("unexpected {other:?}"),
        }
    }
    start.elapsed().as_secs_f64()
}

/// tungstenite's client against our server: isolates the server half.
fn echo_tungstenite_client_on_courierust_server(
    addr: std::net::SocketAddr,
    size: usize,
    count: usize,
) -> f64 {
    let stream = TcpStream::connect(addr).unwrap();
    stream.set_nodelay(true).unwrap();
    let url = format!("ws://{addr}/echo");
    let (mut ws, _) = tungstenite::client(url.as_str(), stream).expect("handshake");
    let payload = vec![0x5au8; size];
    let start = Instant::now();
    for _ in 0..count {
        ws.send(TungMessage::Binary(payload.clone().into()))
            .unwrap();
        let msg = ws.read().unwrap();
        assert_eq!(msg.len(), size);
    }
    start.elapsed().as_secs_f64()
}

/// Pipelined variant with a bounded window: keep `window` frames in
/// flight, then read one echo before sending the next.
///
/// Comparing this with the alternating loop separates *latency* (the cost
/// of waking the peer twice per message) from *throughput* (the cost of
/// framing and moving each message).
///
/// The window is bounded on purpose: an unbounded version fills both
/// socket buffers and deadlocks (the peer blocks writing echoes while we
/// block writing requests), which is a benchmark artifact, not a library
/// property.
fn echo_courierust_pipelined(
    addr: std::net::SocketAddr,
    size: usize,
    count: usize,
    window: usize,
) -> f64 {
    let mut ws = CourierustWs::connect(
        &format!("ws://{addr}/echo"),
        &ClientConfig {
            read_timeout: Some(Duration::from_secs(30)),
            ..Default::default()
        },
    )
    .expect("connect");
    let payload = vec![0x5au8; size];
    let mut inflight = 0usize;
    let mut sent = 0usize;
    let start = Instant::now();
    while sent < count {
        while inflight < window && sent < count {
            ws.send_binary(&payload).unwrap();
            inflight += 1;
            sent += 1;
        }
        match ws.read_message().unwrap() {
            courierust::courierust_ws::Event::Binary(b) => assert_eq!(b.len(), size),
            other => panic!("unexpected {other:?}"),
        }
        inflight -= 1;
    }
    start.elapsed().as_secs_f64()
}

/// The same echo, timed in two halves from the client's point of view:
/// total time spent in `send_binary` and total time spent waiting for the
/// echo. A large-frame gap then belongs to a phase instead of a peer.
fn echo_courierust_phases(addr: std::net::SocketAddr, size: usize, count: usize) -> (f64, f64) {
    let mut ws = CourierustWs::connect(
        &format!("ws://{addr}/echo"),
        &ClientConfig {
            read_timeout: Some(Duration::from_secs(30)),
            ..Default::default()
        },
    )
    .expect("connect");
    let payload = vec![0x5au8; size];
    let mut send = Duration::ZERO;
    let mut recv = Duration::ZERO;
    for _ in 0..count {
        let t = Instant::now();
        ws.send_binary(&payload).unwrap();
        send += t.elapsed();
        let t = Instant::now();
        match ws.read_message().unwrap() {
            courierust::courierust_ws::Event::Binary(b) => assert_eq!(b.len(), size),
            other => panic!("unexpected {other:?}"),
        }
        recv += t.elapsed();
    }
    (send.as_secs_f64(), recv.as_secs_f64())
}

/// The raw-TCP floor: the same loopback path, a 4-byte length prefix and
/// a straight echo, with no WebSocket framing, masking, buffering or
/// protocol state at all.
///
/// This is the ceiling every WebSocket implementation is measured
/// against on this machine — the gap between a row and this one is what
/// the implementation actually costs.
fn echo_tcp_raw(size: usize, count: usize) -> f64 {
    use std::io::{Read, Write};

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.set_nodelay(true).ok();
        let mut head = [0u8; 4];
        let mut buf = Vec::new();
        loop {
            if stream.read_exact(&mut head).is_err() {
                break;
            }
            let n = u32::from_be_bytes(head) as usize;
            buf.resize(n, 0);
            if stream.read_exact(&mut buf).is_err() {
                break;
            }
            if stream.write_all(&head).is_err() || stream.write_all(&buf).is_err() {
                break;
            }
        }
    });

    let mut stream = TcpStream::connect(addr).unwrap();
    stream.set_nodelay(true).unwrap();
    let mut buf = vec![0u8; size + 4];
    buf[4..].copy_from_slice(&vec![0x5au8; size]);
    buf[..4].copy_from_slice(&(size as u32).to_be_bytes());
    let mut inbuf = vec![0u8; size + 4];
    let start = Instant::now();
    for _ in 0..count {
        // One write and one read per message: the cheapest possible
        // request/response exchange on a stream socket, which is why it
        // is the reference every other row is compared against.
        stream.write_all(&buf).unwrap();
        stream.read_exact(&mut inbuf).unwrap();
    }
    let secs = start.elapsed().as_secs_f64();
    drop(stream);
    let _ = server.join();
    secs
}

// ---------------------------------------------------------------------
// Echo loop: tungstenite (blocking, std sockets)
// ---------------------------------------------------------------------

fn start_tungstenite_server() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            std::thread::spawn(move || {
                stream.set_nodelay(true).ok();
                let mut ws = match tungstenite::accept(stream) {
                    Ok(ws) => ws,
                    Err(_) => return,
                };
                while let Ok(msg) = ws.read() {
                    if msg.is_close() {
                        let _ = ws.close(None);
                        break;
                    }
                    if msg.is_text() || msg.is_binary() {
                        if ws.send(msg).is_err() {
                            break;
                        }
                    }
                }
            });
        }
    });
    addr
}

fn echo_tungstenite(addr: std::net::SocketAddr, size: usize, count: usize) -> f64 {
    let stream = TcpStream::connect(addr).unwrap();
    stream.set_nodelay(true).unwrap();
    let url = format!("ws://{addr}/echo");
    let (mut ws, _) = tungstenite::client(url.as_str(), stream).expect("handshake");
    let payload = vec![0x5au8; size];
    let start = Instant::now();
    for _ in 0..count {
        ws.send(TungMessage::Binary(payload.clone().into()))
            .unwrap();
        let msg = ws.read().unwrap();
        assert_eq!(msg.len(), size);
    }
    start.elapsed().as_secs_f64()
}

// ---------------------------------------------------------------------
// Echo loop: tokio-tungstenite (async)
// ---------------------------------------------------------------------

fn echo_tokio_tungstenite(size: usize, count: usize) -> f64 {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async move {
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    continue;
                };
                stream.set_nodelay(true).ok();
                tokio::spawn(async move {
                    let Ok(mut ws) = tokio_tungstenite::accept_async(stream).await else {
                        return;
                    };
                    while let Some(Ok(msg)) = ws.next().await {
                        if msg.is_close() {
                            break;
                        }
                        if ws.send(msg).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });

        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream.set_nodelay(true).unwrap();
        let url = format!("ws://{addr}/echo");
        let (mut ws, _) = tokio_tungstenite::connect_async(url.as_str())
            .await
            .expect("handshake");
        let payload = vec![0x5au8; size];
        let start = Instant::now();
        for _ in 0..count {
            ws.send(TungMessage::Binary(payload.clone().into()))
                .await
                .unwrap();
            let msg = ws.next().await.unwrap().unwrap();
            assert_eq!(msg.len(), size);
        }
        let elapsed = start.elapsed().as_secs_f64();
        server.abort();
        elapsed
    })
}

// ---------------------------------------------------------------------
// main
// ---------------------------------------------------------------------

fn echo_benchmarks() {
    println!("\n== echo loop over loopback TCP (request/response round trips) ==\n");
    let courierust_addr = start_courierust_server();
    // Compression variants are given their own servers so the negotiated
    // extension is per-connection and never leaks between rows.
    let courierust_deflate_addr = start_courierust_server_with(true, true);
    let tungstenite_addr = start_tungstenite_server();

    for &(size, count) in &[(64usize, 20_000usize), (1024, 20_000), (16 * 1024, 5_000), (256 * 1024, 500)] {
        println!("message {size} bytes, {count} round trips");

        // Warmup (page faults, TCP slow start, JIT-free but Rust still
        // has to fault in the code paths).
        let _ = echo_courierust(courierust_addr, size, 100);
        let _ = echo_tungstenite(tungstenite_addr, size, 100);
        let _ = echo_tokio_tungstenite(size, 100);

        let ours: Vec<f64> = (0..3).map(|_| echo_courierust(courierust_addr, size, count)).collect();
        let ours_deflate: Vec<f64> = (0..3)
            .map(|_| echo_courierust_with(courierust_deflate_addr, size, count, true, true))
            .collect();
        let sync_t: Vec<f64> = (0..3).map(|_| echo_tungstenite(tungstenite_addr, size, count)).collect();
        let async_t: Vec<f64> = (0..3).map(|_| echo_tokio_tungstenite(size, count)).collect();
        // Cross pairs: our client on their server and vice versa, so a
        // regression can be attributed to one side instead of guessed at.
        let cross_client: Vec<f64> = (0..3)
            .map(|_| echo_courierust_client_on_tungstenite_server(tungstenite_addr, size, count))
            .collect();
        let cross_server: Vec<f64> = (0..3)
            .map(|_| echo_tungstenite_client_on_courierust_server(courierust_addr, size, count))
            .collect();

        let best = |v: &Vec<f64>| v.iter().cloned().fold(f64::MAX, f64::min);
        let ours = best(&ours);
        let ours_deflate = best(&ours_deflate);
        let sync_t = best(&sync_t);
        let async_t = best(&async_t);
        let cross_client = best(&cross_client);
        let cross_server = best(&cross_server);
        let raw = (0..3)
            .map(|_| echo_tcp_raw(size, count))
            .fold(f64::MAX, f64::min);

        let report = |label: &str, secs: f64| {
            println!(
                "  {label:<34} {:>10.0} msg/s  {:>9.1} MiB/s  ({:>7.2} us/msg)",
                count as f64 / secs,
                mib_per_sec(size * count, secs),
                secs * 1e6 / count as f64
            );
        };
        report("courierust / courierust", ours);
        report("courierust + permessage-deflate", ours_deflate);
        report("tungstenite / tungstenite", sync_t);
        report("tokio-tungstenite / tokio-tungstenite", async_t);
        report("courierust client / tungstenite srv", cross_client);
        report("tungstenite client / courierust srv", cross_server);
        report("raw TCP echo (no framing, floor)", raw);
        println!(
            "  ratios: own/blocking = {:.2}x, own/async = {:.2}x, own/deflate = {:.2}x, own/raw-TCP = {:.2}x\n",
            sync_t / ours,
            async_t / ours,
            ours_deflate / ours,
            raw / ours
        );
    }
}

// ---------------------------------------------------------------------
// One-way push throughput
//
// The echo loop measures a round trip, which mixes four phases together.
// This section measures one direction only — server pushes N messages,
// the client reads them and nothing is sent back — so "who is slow" has
// an answer instead of a guess, and so a streaming workload (the shape a
// fan-out service actually has) has its own number.
// ---------------------------------------------------------------------

/// Parses a `"<size>:<count>"` push command.
fn parse_push_command(text: &str) -> (usize, usize) {
    let mut it = text.trim().split(':');
    let size = it.next().and_then(|v| v.parse().ok()).unwrap_or(0);
    let count = it.next().and_then(|v| v.parse().ok()).unwrap_or(0);
    (size, count)
}

struct PushHandler;
struct PushService;

impl WsService for PushService {
    fn on_message(&self, c: &mut WsConn, msg: WsData) {
        let WsData::Text(t) = msg else { return };
        let (size, count) = parse_push_command(&t);
        let payload = vec![0x5au8; size];
        let start = Instant::now();
        let trace = std::env::var("WS_BENCH_TRACE").is_ok();
        for i in 0..count {
            let t = Instant::now();
            if c.send_binary(&payload).is_err() {
                return;
            }
            if trace && i < 12 {
                println!(
                    "    [srv send #{i}: {:>7.3} ms]",
                    t.elapsed().as_secs_f64() * 1e3
                );
            }
        }
        // Report how long the *server* spent inside `send_binary`: if the
        // peer is slower than the sender, this is where the back-pressure
        // shows up instead of being attributed to "the client read".
        let secs = start.elapsed().as_secs_f64();
        let _ = c.send_text(&format!("done:{:.6}", secs));
    }
}

impl Handler for PushHandler {
    fn handle(&self, _req: Request<Body>) -> Response<Body> {
        Response::with_status(courierust::courierust_http::status::StatusCode::from_u16(404))
    }

    fn websocket(&self, _req: &Request<Body>) -> WsUpgradeReply {
        WsUpgradeReply::Accept(Arc::new(PushService))
    }
}

/// Push server with an explicit decision about socket read deadlines: the
/// liveness timeout is what a keepalive policy is built on, and on Windows
/// it turns out to interact with the peer's own deadline, so the benchmark
/// varies it deliberately.
fn push_server(read_deadline: bool, client_deadline: bool) -> std::net::SocketAddr {
    let _ = client_deadline;
    let config = ServerConfig {
        event_driven: false,
        threads: 2,
        read_timeout: if read_deadline {
            Some(Duration::from_secs(120))
        } else {
            None
        },
        websocket: courierust::courierust_server::ws::WsConfig {
            ping_interval: None,
            compression: courierust::courierust_ws::PmDeflatePolicy {
                enabled: false,
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    };
    let server = Server::bind_with_config("127.0.0.1:0", config).unwrap();
    let addr = server.local_addr().unwrap();
    std::mem::forget(server.serve_background(PushHandler).unwrap());
    addr
}

fn start_tungstenite_push_server() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            std::thread::spawn(move || {
                stream.set_nodelay(true).ok();
                let mut ws = match tungstenite::accept(stream) {
                    Ok(ws) => ws,
                    Err(_) => return,
                };
                // The first message is the push command.
                let Ok(cmd) = ws.read() else { return };
                let (size, count) = parse_push_command(cmd.to_text().unwrap_or(""));
                let payload = vec![0x5au8; size];
                for _ in 0..count {
                    if ws
                        .send(TungMessage::Binary(payload.clone().into()))
                        .is_err()
                    {
                        return;
                    }
                }
            });
        }
    });
    addr
}

fn push_read_courierust(target: &str, count: usize, size: usize) -> f64 {
    push_read_courierust_opts(target, count, size, 64 * 1024, true)
}

fn push_read_courierust_opts(
    target: &str,
    count: usize,
    size: usize,
    read_buffer: usize,
    read_deadline: bool,
) -> f64 {
    let mut ws = CourierustWs::connect_with(
        target,
        &ClientConfig {
            read_timeout: if read_deadline {
                Some(Duration::from_secs(30))
            } else {
                None
            },
            ..Default::default()
        },
        &courierust::courierust_client::ws::WsClientOptions {
            compression: false,
            read_buffer,
            ..Default::default()
        },
    )
    .expect("connect");
    ws.send_text(&format!("{size}:{count}")).unwrap();
    let start = Instant::now();
    let trace = std::env::var("WS_BENCH_TRACE").is_ok();
    for i in 0..count {
        let t = Instant::now();
        match ws.read_message().unwrap() {
            courierust::courierust_ws::Event::Binary(b) => assert_eq!(b.len(), size),
            other => panic!("unexpected {other:?}"),
        }
        if trace && i < 12 {
            println!(
                "    [cli read #{i}: {:>7.3} ms]",
                t.elapsed().as_secs_f64() * 1e3
            );
        }
    }
    let secs = start.elapsed().as_secs_f64();
    // The trailer tells us how much of that time the server spent blocked
    // in `send_binary` (back-pressure) versus how much was the client's
    // own receive path.
    if let Ok(courierust::courierust_ws::Event::Text(t)) = ws.read_message() {
        println!("    [server send-binary total: {t}]", );
    }
    secs
}

fn push_read_tungstenite(target: &str, count: usize, size: usize) -> f64 {
    let addr = target
        .split("//")
        .nth(1)
        .and_then(|rest| rest.split('/').next())
        .unwrap()
        .to_string();
    let stream = TcpStream::connect(addr).unwrap();
    stream.set_nodelay(true).unwrap();
    let (mut ws, _) = tungstenite::client(target, stream).expect("handshake");
    ws.send(TungMessage::Text(format!("{size}:{count}").into()))
        .unwrap();
    let start = Instant::now();
    for _ in 0..count {
        let msg = ws.read().unwrap();
        assert_eq!(msg.len(), size);
    }
    start.elapsed().as_secs_f64()
}

/// Control experiment: a raw TCP server writes the same byte pattern a
/// WebSocket sender produces (a small header write followed by a 256 KiB
/// payload write) and a raw client reads it with the same 64 KiB buffer
/// our session uses.
///
/// If this shows the same multi-millisecond stalls, the stalls belong to
/// the operating system and the access pattern, not to any WebSocket
/// implementation.
fn push_raw_control(size: usize, count: usize) -> f64 {
    use std::io::{Read, Write};
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let head = {
        let mut h = [0x82u8, 0x7f, 0, 0, 0, 0, 0, 4, 0, 0];
        h[2..10].copy_from_slice(&(size as u64).to_be_bytes());
        h
    };
    let server = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream.set_nodelay(true).ok();
        let mut w = stream;
        let payload = vec![0x5au8; size];
        for _ in 0..count {
            if w.write_all(&head).is_err() || w.write_all(&payload).is_err() {
                return;
            }
        }
    });

    let stream = TcpStream::connect(addr).unwrap();
    stream.set_nodelay(true).unwrap();
    let mut r = stream;
    let mut buf = vec![0u8; 64 * 1024];
    let mut need = count * (head.len() + size);
    let start = Instant::now();
    while need > 0 {
        let n = r.read(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        need -= n;
    }
    let secs = start.elapsed().as_secs_f64();
    let _ = server.join();
    secs
}

/// Server pushes `count` messages of `size` bytes; the client only reads.
fn push_benchmarks() {
    println!("\n== one-way push, server -> client (no round trips) ==\n");
    let ours_deadline = push_server(true, true);
    let ours_nodeadline = push_server(false, false);
    let theirs = start_tungstenite_push_server();

    for &(size, count) in &[(16 * 1024usize, 20_000usize), (256 * 1024, 500)] {
        let ours_url = format!("ws://{ours_deadline}/push");
        let ours_nodeadline_url = format!("ws://{ours_nodeadline}/push");
        let theirs_url = format!("ws://{theirs}/push");
        let report = |label: &str, secs: f64| {
            println!(
                "  {label:<34} {:>10.0} msg/s  {:>9.1} MiB/s  ({:>7.2} us/msg)",
                count as f64 / secs,
                mib_per_sec(size * count, secs),
                secs * 1e6 / count as f64
            );
        };
        println!("message {size} bytes, {count} messages, one direction");

        // Warmup.
        let _ = push_read_courierust(&ours_url, 20, size);
        let _ = push_read_tungstenite(&theirs_url, 20, size);

        let best = |v: Vec<f64>| v.iter().cloned().fold(f64::MAX, f64::min);
        let ours_reads = best((0..3).map(|_| push_read_courierust(&ours_url, count, size)).collect());
        let ours_reads_no_deadline = best(
            (0..3)
                .map(|_| push_read_courierust_opts(&ours_url, count, size, 64 * 1024, false))
                .collect(),
        );
        let ours_both_no_deadline = best(
            (0..3)
                .map(|_| {
                    push_read_courierust_opts(&ours_nodeadline_url, count, size, 64 * 1024, false)
                })
                .collect(),
        );
        let ours_client_deadline_only = best(
            (0..3)
                .map(|_| {
                    push_read_courierust_opts(&ours_nodeadline_url, count, size, 64 * 1024, true)
                })
                .collect(),
        );
        let ours_client_theirs_server =
            best((0..3).map(|_| push_read_courierust(&theirs_url, count, size)).collect());
        let theirs_client_ours_server =
            best((0..3).map(|_| push_read_tungstenite(&ours_url, count, size)).collect());
        let theirs_reads =
            best((0..3).map(|_| push_read_tungstenite(&theirs_url, count, size)).collect());

        report("courierust srv -> courierust client", ours_reads);
        report("  ... client deadline off", ours_reads_no_deadline);
        report("  ... both deadlines off", ours_both_no_deadline);
        report("  ... client deadline only", ours_client_deadline_only);
        report("tungstenite srv -> courierust client", ours_client_theirs_server);
        report("courierust srv -> tungstenite client", theirs_client_ours_server);
        report("tungstenite srv -> tungstenite client", theirs_reads);
        report(
            "raw TCP, same write pattern",
            best((0..3).map(|_| push_raw_control(size, count)).collect()),
        );
        println!(
            "  ratios: own/blocking = {:.2}x\n",
            theirs_reads / ours_reads
        );
    }
}

fn main() {
    println!("courierust WebSocket benchmark");
    println!(
        "machine: {} logical cores",
        std::thread::available_parallelism().map(|n| n.get()).unwrap_or(0)
    );
    // `WS_BENCH_SECTION=push` (or `codec`, `echo`) runs one section only:
    // useful while investigating a single number.
    match std::env::var("WS_BENCH_SECTION").as_deref() {
        Ok("push") => {
            push_benchmarks();
            return;
        }
        Ok("echo") => {
            echo_benchmarks();
            return;
        }
        Ok("codec") => {
            codec_benchmarks();
            return;
        }
        _ => {}
    }
    codec_benchmarks();
    echo_benchmarks();
    push_benchmarks();
    read_buffer_sensitivity();
    phase_split();
    timeout_sensitivity();
}

/// Large-frame cost is dominated by how many bytes each transport read
/// carries, and that number is the buffer the protocol layer offers the
/// socket. This section measures the same 256 KiB echo with two buffer
/// sizes so the recommendation (and the default) is evidence-backed
/// rather than folklore.
fn read_buffer_sensitivity() {
    const SIZE: usize = 256 * 1024;
    const COUNT: usize = 500;
    println!("\n== read-buffer sensitivity (256 KiB echo, both ends ours) ==\n");
    for buffer in [16 * 1024usize, 64 * 1024, 256 * 1024] {
        let addr = start_courierust_server_tuned(true, false, buffer);
        let _ = echo_courierust_tuned(addr, SIZE, 20, true, false, buffer);
        let secs = (0..3)
            .map(|_| echo_courierust_tuned(addr, SIZE, COUNT, true, false, buffer))
            .fold(f64::MAX, f64::min);
        println!(
            "  buffer {:>7} bytes             {:>9.0} msg/s  ({:>7.2} us/msg)",
            buffer,
            COUNT as f64 / secs,
            secs * 1e6 / COUNT as f64
        );
    }
    println!();
}

/// Where the time goes: the same 256 KiB echo split into the client's
/// send phase and its wait-for-echo phase, against our server and against
/// tungstenite's. A gap that only appears when both ends are ours belongs
/// to a phase of one side, not to "the codec".
fn phase_split() {
    const SIZE: usize = 256 * 1024;
    const COUNT: usize = 500;
    println!("\n== phase split, client view (256 KiB echo, {COUNT} round trips) ==\n");
    let ours = start_courierust_server();
    let theirs = start_tungstenite_server();
    let _ = echo_courierust(ours, SIZE, 20);
    let _ = echo_courierust_client_on_tungstenite_server(theirs, SIZE, 20);
    let run = |label: &str, addr| {
        let mut best = (f64::MAX, f64::MAX);
        for _ in 0..3 {
            let (send, recv) = echo_courierust_phases(addr, SIZE, COUNT);
            if send + recv < best.0 + best.1 {
                best = (send, recv);
            }
        }
        println!(
            "  {label:<34} send {:>7.2} us   wait {:>7.2} us   total {:>7.2} us",
            best.0 * 1e6 / COUNT as f64,
            best.1 * 1e6 / COUNT as f64,
            (best.0 + best.1) * 1e6 / COUNT as f64
        );
    };
    run("courierust client -> courierust srv", ours);
    run("courierust client -> tungstenite srv", theirs);
    println!();
}

/// Socket-level read timeouts are what a keepalive story is built on, and
/// on Windows a socket with `SO_RCVTIMEO` set parks differently from one
/// without. This section measures that cost explicitly, for both peers,
/// so the production recommendation is backed by a number instead of a
/// guess.
fn timeout_sensitivity() {
    println!("\n== socket read-timeout sensitivity (64-byte echo) ==\n");
    const COUNT: usize = 20_000;

    let with_timeouts = start_courierust_server_with(true, false);
    let without = start_courierust_server_with(false, false);

    let warm = |addr| {
        let _ = echo_courierust_with(addr, 64, 200, true, false);
        let _ = echo_courierust_with(addr, 64, 200, false, false);
    };
    warm(with_timeouts);
    warm(without);

    let run = |label: &str, addr, client_timeout: bool| {
        let secs = (0..3)
            .map(|_| echo_courierust_with(addr, 64, COUNT, client_timeout, false))
            .fold(f64::MAX, f64::min);
        println!(
            "  {label:<44} {:>9.0} msg/s  ({:>6.2} µs/msg)",
            COUNT as f64 / secs,
            secs * 1e6 / COUNT as f64
        );
    };
    run("server+client deadlines (default)", with_timeouts, true);
    run("server deadlines, client none", with_timeouts, false);
    run("no deadlines (raw liveness-free loop)", without, false);

    // Latency vs throughput, on the same socket and payload.
    println!("\n== alternating vs windowed pipeline (64-byte messages) ==\n");
    let best = |v: Vec<f64>| v.iter().cloned().fold(f64::MAX, f64::min);
    let alternating = best(
        (0..3)
            .map(|_| echo_courierust(with_timeouts, 64, COUNT))
            .collect(),
    );
    for window in [8usize, 64, 512] {
        let pipelined = best(
            (0..3)
                .map(|_| echo_courierust_pipelined(with_timeouts, 64, COUNT, window))
                .collect(),
        );
        println!(
            "  window {window:>4} outstanding        {:>9.0} msg/s  ({:>6.2} us/msg)  {:.2}x alternating",
            COUNT as f64 / pipelined,
            pipelined * 1e6 / COUNT as f64,
            alternating / pipelined
        );
    }
    println!(
        "  alternating round trips        {:>9.0} msg/s  ({:>6.2} us/msg)",
        COUNT as f64 / alternating,
        alternating * 1e6 / COUNT as f64
    );
    println!();
}
