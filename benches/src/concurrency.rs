//! Slow-connection and idle-connection evidence for the server scheduler.
//!
//! The benchmark uses incomplete HTTP/1.1 headers to create connections that
//! are connected but cannot yet be dispatched to the handler. The default
//! event-driven scheduler (all platforms) keeps these connections out of the
//! worker pool, so the probe completes. The `pool` case forces the legacy
//! one-blocking-job-per-connection model and is reported explicitly; it is
//! the diagnostic that shows *why* the event-driven scheduler is the default.

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
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("set partial read timeout");
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
    let event_driven = model == "event";
    let server = Server::bind_with_config(
        "127.0.0.1:0",
        ServerConfig {
            http2: false,
            threads: 2,
            event_driven,
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
            "CONCURRENCY|case=idle_partial_herd|model={model}|platform={}|status=probe_ok|event_enabled={event_driven}|connections={idle}|worker_threads=2|probe_us={:.2}",
            std::env::consts::OS,
            elapsed.as_secs_f64() * 1_000_000.0,
        ),
        Err(error) => println!(
            "CONCURRENCY|case=idle_partial_herd|model={model}|platform={}|status=probe_blocked|event_enabled={event_driven}|connections={idle}|worker_threads=2|probe_us=na|error={}",
            std::env::consts::OS,
            error.replace('|', "/"),
        ),
    }
    drop(herd);
}

/// The complete request header a slow connection trickles byte-by-byte.
const SLOW_HEADER: &[u8] = b"GET /slow HTTP/1.1\r\nHost: benchmark\r\n\r\n";

/// A genuinely slow sender: each connection delivers its request header
/// one byte at a time with a real sleep between bytes, so the server must
/// keep servicing a fast probe *while* `count` connections are
/// mid-request. The previous version wrote the trailing CRLF all at once,
/// so every "slow" connection finished in ~1 ms — it measured nothing.
///
/// The probe runs concurrently with the trickle; it must complete within
/// `PROBE_TIMEOUT` or the event-driven scheduler is not actually keeping
/// slow senders off the workers.
fn run_slow_sender_case(count: usize) {
    let event_driven = true;
    let server = Server::bind_with_config(
        "127.0.0.1:0",
        ServerConfig {
            http2: false,
            threads: 2,
            event_driven,
            event_workers: 2,
            ..Default::default()
        },
    )
    .expect("bind slow sender server");
    let addr = server.local_addr().expect("slow sender server address");
    let _handle = server
        .serve_background(handler)
        .expect("start slow sender server");

    // Phase 1: open all connections and trickle their headers in
    // parallel. Each byte is preceded by a real delay, so the connection
    // is provably in the middle of a request while the probe runs.
    let byte_delay = Duration::from_millis(
        env_usize("COURIERUST_SLOW_BYTE_DELAY_MS", 10) as u64,
    );
    let started = Instant::now();
    let mut handles = Vec::with_capacity(count);
    for index in 0..count {
        let mut stream = TcpStream::connect(addr)
            .unwrap_or_else(|e| panic!("connect slow connection {index}: {e}"));
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("set slow read timeout");
        handles.push(std::thread::spawn(move || {
            for &byte in SLOW_HEADER {
                std::thread::sleep(byte_delay);
                stream
                    .write_all(&[byte])
                    .unwrap_or_else(|e| panic!("slow trickle byte: {e}"));
            }
            read_full_response(&mut stream)
        }));
    }

    // Phase 2: while every connection is still trickling (they cannot
    // have finished: `count * SLOW_HEADER.len()` bytes remain after the
    // first byte), a fast probe must complete promptly. This is the
    // actual Slowloris-resistance assertion.
    let probe_result = probe(addr);

    // Phase 3: let the trickles finish and verify every slow sender gets
    // its full response (the server did not stall or drop them).
    let mut completed = 0usize;
    for handle in handles {
        if handle.join().expect("slow sender thread panicked").is_ok() {
            completed += 1;
        }
    }
    let probe_us = match &probe_result {
        Ok(elapsed) => elapsed.as_secs_f64() * 1_000_000.0,
        Err(_) => f64::NAN,
    };
    let probe_status = match probe_result {
        Ok(_) => "probe_ok",
        Err(error) => {
            eprintln!("slow-sender herd blocked the fast path: {error}");
            "probe_blocked"
        }
    };
    println!(
        "CONCURRENCY|case=slow_sender_herd|model=event|platform={}|status={}|event_enabled={event_driven}|connections={count}|worker_threads=2|completed={completed}|probe_status={probe_status}|probe_us={probe_us:.2}|byte_delay_us={}|wall_ms={:.2}",
        std::env::consts::OS,
        if completed == count && probe_status == "probe_ok" {
            "ok"
        } else {
            "partial"
        },
        byte_delay.as_micros(),
        started.elapsed().as_secs_f64() * 1000.0,
    );
}

fn main() {
    let idle = env_usize("COURIERUST_IDLE_CONNS", IDLE_CONNS);
    run_idle_case("event", idle);
    run_idle_case("pool", idle);
    run_slow_sender_case(env_usize("COURIERUST_SLOW_CONNS", SLOW_CONNS));
    println!("CONCURRENCY|suite=complete");
}
