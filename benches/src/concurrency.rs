//! Concurrency benchmark: does a herd of idle keep-alive connections
//! degrade request latency?
//!
//! The event-driven server parks idle connections on a poller (zero
//! workers), so with only two event workers the request P50/P99 should
//! stay flat as idle connections grow. The per-connection pool model
//! instead burns one worker per idle connection, so a small pool stalls
//! once the herd exceeds it.
//!
//! Run: `cargo bench --bench concurrency` (or
//! `cargo run --release --bench concurrency`).

use courierust::body::Body;
use courierust::bytes::Bytes;
use courierust::client::{Client, ClientConfig};
use courierust::http::request::Request;
use courierust::http::response::Response;
use courierust::server::{Server, ServerConfig};
use std::io::{Read as _, Write as _};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

const IDLE_CONNS: usize = 200;
const REQS: usize = 400;

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|v| *v > 0)
        .unwrap_or(default)
}

fn handler(_req: Request<Body>) -> Response<Body> {
    let mut resp = Response::with_status(200.into());
    resp.headers.insert(
        courierust::http::header::HeaderName::from_lowercase("content-length"),
        courierust::http::header::HeaderValue::from_static("2"),
    );
    resp.body = Body::Bytes(Bytes::from_static(b"ok"));
    resp
}

fn read_full_response(stream: &mut TcpStream) {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let mut head_end = None;
    while head_end.is_none() {
        let n = stream.read(&mut tmp).unwrap();
        if n == 0 {
            panic!("eof");
        }
        buf.extend_from_slice(&tmp[..n]);
        head_end = buf.windows(4).position(|w| w == b"\r\n\r\n");
    }
    let he = head_end.unwrap() + 4;
    let head = String::from_utf8_lossy(&buf[..he]);
    let cl: usize = head
        .lines()
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            if k.eq_ignore_ascii_case("content-length") {
                v.trim().parse().ok()
            } else {
                None
            }
        })
        .unwrap_or(0);
    while buf.len() < he + cl {
        let n = stream.read(&mut tmp).unwrap();
        buf.extend_from_slice(&tmp[..n]);
    }
}

/// Open `n` keep-alive connections that send one request each and stay
/// idle.
fn open_idle_herd(addr: std::net::SocketAddr, n: usize) -> Vec<TcpStream> {
    let mut herd = Vec::with_capacity(n);
    for _ in 0..n {
        let mut s = TcpStream::connect(addr).unwrap();
        s.write_all(b"GET /idle HTTP/1.1\r\nHost: x\r\n\r\n")
            .unwrap();
        read_full_response(&mut s);
        herd.push(s);
    }
    herd
}

fn main() {
    let idle = env_usize("COURIERUST_IDLE_CONNS", IDLE_CONNS);
    let reqs = env_usize("COURIERUST_REQS", REQS);

    for model in ["event", "pool"] {
        let server_cfg = ServerConfig {
            http2: false,
            threads: 2,
            event_driven: model == "event",
            event_workers: 2,
            ..Default::default()
        };
        let server = Server::bind_with_config("127.0.0.1:0", server_cfg).unwrap();
        let addr = server.local_addr().unwrap();
        let _handle = server.serve_background(handler).unwrap();

        // Warm the acceptor, then open the idle herd.
        let mut warm = TcpStream::connect(addr).unwrap();
        warm.write_all(b"GET /warm HTTP/1.1\r\nHost: x\r\n\r\n")
            .unwrap();
        read_full_response(&mut warm);
        drop(warm);

        let herd = open_idle_herd(addr, idle);

        // Measure sequential fresh requests while the herd sits idle.
        let client = Client::with_config(ClientConfig {
            max_connections_per_host: 1,
            ..Default::default()
        });
        let mut samples = Vec::with_capacity(reqs);
        for _ in 0..reqs {
            let t0 = Instant::now();
            let resp = client.get(&format!("http://{addr}/r")).unwrap();
            assert_eq!(resp.status.as_u16(), 200);
            samples.push(t0.elapsed());
        }
        samples.sort_unstable();
        let p50 = samples[reqs / 2].as_secs_f64() * 1_000_000.0;
        let p75 = samples[(reqs as f64 * 0.75) as usize].as_secs_f64() * 1_000_000.0;
        let p90 = samples[(reqs as f64 * 0.90) as usize].as_secs_f64() * 1_000_000.0;
        let p95 = samples[(reqs as f64 * 0.95) as usize].as_secs_f64() * 1_000_000.0;
        let p99 = samples[(reqs as f64 * 0.99) as usize].as_secs_f64() * 1_000_000.0;

        println!(
            "model={model} idle={idle} workers=2 reqs={reqs} p50_us={p50:.1} p75_us={p75:.1} p90_us={p90:.1} p95_us={p95:.1} p99_us={p99:.1}",
        );
        drop(herd);
    }

    // Idle-connection benchmark with a slow-sender herd (partial requests
    // that stall): with the event loop these are parked, with the pool
    // model they each hold a worker.
    let slow_idle = env_usize("COURIERUST_SLOW_CONNS", 16);
    let server_cfg = ServerConfig {
        http2: false,
        threads: 2,
        event_driven: true,
        event_workers: 2,
        ..Default::default()
    };
    let server = Server::bind_with_config("127.0.0.1:0", server_cfg).unwrap();
    let addr = server.local_addr().unwrap();
    let _handle = server.serve_background(handler).unwrap();
    let mut slow: Vec<TcpStream> = Vec::new();
    for _ in 0..slow_idle {
        let mut s = TcpStream::connect(addr).unwrap();
        // Send a partial request and stall.
        s.write_all(b"GET /slow HTTP/1.1\r\nHost: x\r\n").unwrap();
        slow.push(s);
    }
    let t0 = Instant::now();
    let mut done = 0;
    for s in slow.iter_mut() {
        s.write_all(b"\r\n").unwrap();
        read_full_response(s);
        done += 1;
    }
    println!(
        "event slow-sender herd: slow={slow_idle} workers=2 completed={done} wall_ms={:.1}",
        t0.elapsed().as_secs_f64() * 1000.0
    );
    let _ = Arc::new(());
    let _ = Duration::from_secs(0);
}
