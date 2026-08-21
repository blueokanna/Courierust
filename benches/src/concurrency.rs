//! Slow-connection and idle-connection evidence for the server scheduler.
//!
//! The benchmark uses incomplete HTTP/1.1 headers to create connections that
//! are connected but cannot yet be dispatched to the handler. On Windows the
//! event-driven scheduler should keep these connections out of the worker
//! pool. On other platforms the blocking pool behaviour is measured and
//! reported explicitly; it is not mislabeled as event-driven evidence.

use courierust::courierust_body::Body;
use courierust::courierust_bytes::Bytes;
use courierust::courierust_http::header::{HeaderName, HeaderValue};
use courierust::courierust_http::request::Request;
use courierust::courierust_http::response::Response;
use courierust::courierust_server::{Server, ServerConfig};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

const IDLE_CONNS: usize = 200;
const SLOW_CONNS: usize = 16;
const PROBE_TIMEOUT: Duration = Duration::from_millis(500);

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
        HeaderName::from_lowercase("content-length"),
        HeaderValue::from_static("2"),
    );
    resp.body = Body::Bytes(Bytes::from_static(b"ok"));
    resp
}

fn read_full_response(stream: &mut TcpStream) -> std::io::Result<()> {
    let mut buf = Vec::with_capacity(256);
    let mut tmp = [0u8; 4096];
    let header_end = loop {
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "peer closed before response headers",
            ));
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
    };
    let header = String::from_utf8_lossy(&buf[..header_end]);
    let content_length = header
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);
    while buf.len() < header_end + content_length {
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "peer closed before response body",
            ));
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    Ok(())
}

/// Open connections with a complete request line but no terminating CRLF.
/// They are intentionally slow readers from the server's perspective.
fn open_partial_herd(addr: SocketAddr, count: usize) -> Vec<TcpStream> {
    let mut herd = Vec::with_capacity(count);
    for index in 0..count {
        let mut stream = TcpStream::connect(addr)
            .unwrap_or_else(|e| panic!("connect partial connection {index}: {e}"));
        stream
            .set_write_timeout(Some(PROBE_TIMEOUT))
            .expect("set partial write timeout");
        stream
            .write_all(b"GET /slow HTTP/1.1\r\nHost: benchmark\r\n")
            .unwrap_or_else(|e| panic!("write partial connection {index}: {e}"));
        herd.push(stream);
    }
    herd
}

fn probe(addr: SocketAddr) -> Result<Duration, String> {
    let started = Instant::now();
    let mut stream = TcpStream::connect(addr).map_err(|e| format!("connect: {e}"))?;
    stream
        .set_read_timeout(Some(PROBE_TIMEOUT))
        .map_err(|e| format!("set read timeout: {e}"))?;
    stream
        .set_write_timeout(Some(PROBE_TIMEOUT))
        .map_err(|e| format!("set write timeout: {e}"))?;
    stream
        .write_all(b"GET /fast HTTP/1.1\r\nHost: benchmark\r\n\r\n")
        .map_err(|e| format!("write: {e}"))?;
    read_full_response(&mut stream).map_err(|e| format!("read: {e}"))?;
    Ok(started.elapsed())
}

fn run_idle_case(model: &'static str, idle: usize) {
    let event_enabled = cfg!(windows) && model == "event";
    let server = Server::bind_with_config(
        "127.0.0.1:0",
        ServerConfig {
            http2: false,
            threads: 2,
            event_driven: event_enabled,
            event_workers: 2,
            ..Default::default()
        },
    )
    .expect("bind concurrency server");
    let addr = server.local_addr().expect("concurrency server address");
    let _handle = server
        .serve_background(handler)
        .expect("start concurrency server");
    let herd = open_partial_herd(addr, idle);
    let result = probe(addr);
    match result {
        Ok(elapsed) => println!(
            "CONCURRENCY|case=idle_partial_herd|model={model}|platform={}|status=probe_ok|event_enabled={event_enabled}|connections={idle}|worker_threads=2|probe_us={:.2}",
            std::env::consts::OS,
            elapsed.as_secs_f64() * 1_000_000.0,
        ),
        Err(error) => println!(
            "CONCURRENCY|case=idle_partial_herd|model={model}|platform={}|status=probe_blocked|event_enabled={event_enabled}|connections={idle}|worker_threads=2|probe_us=na|error={}",
            std::env::consts::OS,
            error.replace('|', "/"),
        ),
    }
    drop(herd);
}

fn run_slow_sender_case(count: usize) {
    let event_enabled = cfg!(windows);
    let server = Server::bind_with_config(
        "127.0.0.1:0",
        ServerConfig {
            http2: false,
            threads: 2,
            event_driven: event_enabled,
            event_workers: 2,
            ..Default::default()
        },
    )
    .expect("bind slow sender server");
    let addr = server.local_addr().expect("slow sender server address");
    let _handle = server
        .serve_background(handler)
        .expect("start slow sender server");
    let mut herd = open_partial_herd(addr, count);
    let started = Instant::now();
    let mut completed = 0usize;
    for stream in &mut herd {
        if stream.write_all(b"\r\n").is_ok() && read_full_response(stream).is_ok() {
            completed += 1;
        }
    }
    println!(
        "CONCURRENCY|case=slow_sender_herd|model={}|platform={}|status={}|event_enabled={event_enabled}|connections={count}|worker_threads=2|completed={completed}|wall_ms={:.2}",
        if event_enabled { "event" } else { "pool" },
        std::env::consts::OS,
        if completed == count { "ok" } else { "partial" },
        started.elapsed().as_secs_f64() * 1000.0,
    );
}

fn main() {
    let idle = env_usize("COURIERUST_IDLE_CONNS", IDLE_CONNS);
    if cfg!(windows) {
        run_idle_case("event", idle);
        run_idle_case("pool", idle);
    } else {
        run_idle_case("pool", idle);
    }
    run_slow_sender_case(env_usize("COURIERUST_SLOW_CONNS", SLOW_CONNS));
    println!("CONCURRENCY|suite=complete");
}
