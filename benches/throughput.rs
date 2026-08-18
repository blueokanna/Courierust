//! Zero-dependency throughput benchmarks (std only, no criterion).
//!
//! Run with `cargo bench --bench throughput`. Every case prints one line
//! that the GitHub Actions benchmark workflow parses:
//!
//! ```text
//! <name>: <N> req/s (total=<seconds>, n=<count>, workers=<w>)
//! ```
//!
//! The cases mirror what the crate actually claims:
//! * `h1_sequential` — HTTP/1.1 keep-alive round-trip latency on one conn;
//! * `h1_concurrent` — HTTP/1.1 across `workers` threads (pool sharding);
//! * `h2_multiplex`  — many streams on a single HTTP/2 connection;
//! * `h2_priority`   — RFC 9218 priority: high-urgency stream wins.

use courierust::body::Body;
use courierust::client::{Client, ClientConfig};
use courierust::h2::priority::Priority;
use courierust::http::request::Request;
use courierust::http::response::Response;
use courierust::server::{Server, ServerConfig};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

fn echo_handler(req: Request<Body>) -> Response<Body> {
    let mut resp = Response::<Body>::with_status(200.into());
    let body = req.body.collect().unwrap_or_default();
    resp.body = Body::Bytes(body);
    resp
}

fn spawn_server(cfg: ServerConfig) -> SocketAddr {
    let server = Server::bind_with_config("127.0.0.1:0", cfg).unwrap();
    let addr = server.local_addr().unwrap();
    let handle = server.serve_background(echo_handler).unwrap();
    std::mem::forget(handle); // keep serving for the whole bench process
    addr
}

fn report(name: &str, n: usize, workers: usize, elapsed: Duration) {
    let per_sec = n as f64 / elapsed.as_secs_f64();
    println!(
        "{name}: {per_sec:.0} req/s (total={elapsed:.3}s, n={n}, workers={workers})",
        elapsed = elapsed.as_secs_f64()
    );
}

fn report_latency(name: &str, elapsed: Duration, workers: usize) {
    println!(
        "{name}: {:.2} ms (high-urgency completion, workers={workers})",
        elapsed.as_secs_f64() * 1000.0
    );
}

fn bench_h1_sequential() {
    let addr = spawn_server(ServerConfig::default());
    let client = Client::new();
    let url = format!("http://{addr}/bench");

    // Warm up the keep-alive connection.
    let _ = client.get(&url).unwrap();

    const N: usize = 20_000;
    let start = Instant::now();
    for _ in 0..N {
        let resp = client.get(&url).unwrap();
        debug_assert_eq!(resp.status.as_u16(), 200);
    }
    report("h1_sequential", N, 1, start.elapsed());
}

fn bench_h1_concurrent() {
    let addr = spawn_server(ServerConfig::default());
    let url = Arc::new(format!("http://{addr}/bench"));

    const WORKERS: usize = 8;
    const PER_WORKER: usize = 2_000;

    // One client per worker: each owns its shard of the keep-alive pool.
    let clients: Vec<Client> = (0..WORKERS).map(|_| Client::new()).collect();

    let start = Instant::now();
    let handles: Vec<_> = clients
        .into_iter()
        .map(|client| {
            let url = url.clone();
            std::thread::spawn(move || {
                for _ in 0..PER_WORKER {
                    let resp = client.get(&url).unwrap();
                    debug_assert_eq!(resp.status.as_u16(), 200);
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    report(
        "h1_concurrent",
        WORKERS * PER_WORKER,
        WORKERS,
        start.elapsed(),
    );
}

fn bench_h2_multiplex() {
    let cfg = ServerConfig {
        http2: true,
        ..Default::default()
    };
    let addr = spawn_server(cfg);
    let client_cfg = ClientConfig {
        http2: true,
        ..Default::default()
    };
    let client = Client::with_config(client_cfg);
    let url = format!("http://{addr}/bench");

    // Warm up (opens the h2 connection).
    let _ = client.get(&url).unwrap();

    // 32 threads hammer the shared (≤4) h2 connections; streams from all
    // of them interleave on the same connections.
    const WORKERS: usize = 32;
    const PER_WORKER: usize = 200;
    let start = Instant::now();
    let handles: Vec<_> = (0..WORKERS)
        .map(|_| {
            let client = client.clone();
            let url = url.clone();
            std::thread::spawn(move || {
                for _ in 0..PER_WORKER {
                    let resp = client.get(&url).unwrap();
                    debug_assert_eq!(resp.status.as_u16(), 200);
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    report(
        "h2_multiplex",
        WORKERS * PER_WORKER,
        WORKERS,
        start.elapsed(),
    );
}

fn bench_h2_priority() {
    let cfg = ServerConfig {
        http2: true,
        ..Default::default()
    };
    let addr = spawn_server(cfg);
    let client_cfg = ClientConfig {
        http2: true,
        ..Default::default()
    };
    let client = Client::with_config(client_cfg);
    let url = format!("http://{addr}/bench");

    let high = Priority {
        urgency: 0,
        incremental: false,
    };
    let low = Priority {
        urgency: 7,
        incremental: false,
    };

    // Measure the total time to finish one high-urgency request launched
    // *after* a pile of low-urgency ones — the scheduler should not let
    // the low-urgency backlog starve or delay it.
    let mut lows = Vec::with_capacity(64);
    for _ in 0..64 {
        let client = client.clone();
        let url = url.clone();
        lows.push(std::thread::spawn(move || {
            let req = Request::new(courierust::http::method::Method::GET, "/low");
            let _ = client.execute_priority(&url, req, low);
        }));
    }

    let start = Instant::now();
    let req = Request::new(courierust::http::method::Method::GET, "/high");
    let resp = client.execute_priority(&url, req, high).unwrap();
    debug_assert_eq!(resp.status.as_u16(), 200);
    let high_elapsed = start.elapsed();

    for h in lows {
        let _ = h.join();
    }
    report_latency("h2_priority_high_latency", high_elapsed, 64);
}

fn main() {
    let started = Instant::now();
    println!("courierust benchmarks (release, std)");
    bench_h1_sequential();
    bench_h1_concurrent();
    bench_h2_multiplex();
    bench_h2_priority();
    println!("total: {:.3}s", started.elapsed().as_secs_f64());
}
