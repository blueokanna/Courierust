//! HTTP/3 (QUIC v1 + TLS 1.3) performance over the pooled connection.
//!
//! One pooled QUIC connection per authority: `h3_sequential`/`h3_parallel`
//! measure the *warm* per-request cost (a single round trip on an established
//! connection). The *cold* cost (QUIC handshake + TLS 1.3 + server Retry
//! address validation) is reported separately as `h3_connect`; the gap
//! between `h3_connect` and `h3_sequential` is exactly what connection
//! reuse buys.
//!
//! Env: `BENCH_REQUESTS` (default 1000), `H3_WORKERS` (default 8).
//!
//! Baseline (Windows 11, loopback, release, 2026-08-22):
//! - `h3_connect`:      ~6-8 ms (cold)
//! - `h3_sequential`:   ~3.5-5.4k rps, p50 ~170-260 µs, p99 ~0.3-0.6 ms
//! - `h3_parallel`×8:   ~9-12k rps, p50 ~0.5-0.9 ms
//!
//! Tail note: `h3_parallel` p99 can jump (µs→ms) on shared runners. The
//! emitted p999/tail_ratio/stddev exist to track that — a single run is a
//! signal, not a root cause (UDP reactor, packet queue, cwnd/ACK timers,
//! QPACK/control flow, worker→reactor handoff, CI scheduling all shape it).
//!
//! The poller raises the Windows timer to 1 ms (`timeBeginPeriod`), which
//! removed ~1 ms periodic `select()` wakeup stalls (p99 10.7 ms → ~0.3 ms).

use courierust::courierust_client::{Client, ClientConfig, TlsSettings as ClientTls};
use courierust::courierust_http::request::Request;
use courierust::courierust_http::response::Response;
use courierust::courierust_server::{Server, ServerConfig, TlsSettings as ServerTls};
use courierust_benchmark::metrics::{run_concurrent, run_sequential, stats_fields, Timing, MAX_SAMPLES};
use std::time::Instant;

const CERT_DER: &[u8] = include_bytes!("../../tests/certs/server_cert.der");
const KEY_DER: &[u8] = include_bytes!("../../tests/certs/server_key.der");

fn report(label: &str, workers: usize, timing: &Timing) {
    println!(
        "RESULT|suite=h3|case={label}|protocol=h3|mode=reuse|payload=empty|bytes=0|workers={workers}|requests={}|elapsed_ms={:.3}|rps={:.1}|p50_us={:.1}|p75_us={:.1}|p90_us={:.1}|p99_us={:.1}|{}|samples={}",
        timing.requests,
        timing.elapsed.as_secs_f64() * 1000.0,
        timing.requests_per_second(),
        timing.percentile_us(0.50).unwrap_or(0.0),
        timing.percentile_us(0.75).unwrap_or(0.0),
        timing.percentile_us(0.90).unwrap_or(0.0),
        timing.percentile_us(0.99).unwrap_or(0.0),
        stats_fields(timing),
        timing.samples.len(),
    );
}

fn main() {
    let requests = std::env::var("BENCH_REQUESTS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1000);
    let workers = std::env::var("H3_WORKERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8);

    let identity = courierust::courierust_tls::Identity {
        cert_chain: vec![CERT_DER.to_vec()],
        private_key: KEY_DER.to_vec(),
        is_rsa: false,
    };
    let server_cfg = ServerConfig {
        http3: true,
        tls: Some(ServerTls {
            identity,
            alpn: vec![b"h3".to_vec()],
        }),
        ..Default::default()
    };
    let server = Server::bind_with_config("127.0.0.1:0", server_cfg).unwrap();
    let addr = server.local_addr().unwrap();
    let _handle = server
        .serve_background(|_req: Request<courierust::courierust_body::Body>| {
            Response::with_status(200.into())
        })
        .unwrap();

    let mut roots = courierust::courierust_tls::RootStore::new();
    roots.add_der(CERT_DER.to_vec());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let client_cfg = ClientConfig {
        http3: true,
        tls: Some(ClientTls {
            roots,
            verify: true,
            alpn: vec![b"h3".to_vec()],
            now,
        }),
        ..Default::default()
    };
    let client = Client::with_config(client_cfg.clone());
    let url = format!("https://{addr}/bench");

    // 1. Cold path: a fresh client pays the full QUIC handshake + TLS 1.3
    //    + server Retry address validation once.
    let cold = Client::with_config(client_cfg);
    let started = Instant::now();
    let _ = cold.get(&url).unwrap();
    println!(
        "RESULT|suite=h3|case=h3_connect|protocol=h3|mode=connect|payload=empty|bytes=0|workers=1|requests=1|connect_ms={:.3}",
        started.elapsed().as_secs_f64() * 1000.0,
    );
    drop(cold);

    // Warm-up on the pooled client (opens the pooled connection).
    for _ in 0..3 {
        let _ = client.get(&url).unwrap();
    }

    // 2. Warm sequential: every request reuses the pooled connection.
    let mut seq = run_sequential(requests, MAX_SAMPLES, || {
        let _ = client.get(&url);
    });
    seq.sort_samples();
    report("h3_sequential", 1, &seq);

    // 3. Warm concurrent: workers share the pooled connection(s) and
    //    multiplex request streams over QUIC.
    let mut conc = run_concurrent(requests, workers, MAX_SAMPLES, |_| {
        let client = client.clone();
        let url = url.clone();
        Box::new(move || {
            let _ = client.get(&url);
        })
    });
    conc.sort_samples();
    report("h3_parallel", workers, &conc);
}
