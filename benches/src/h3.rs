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

use courierust::courierust_body::Body;
use courierust::courierust_bytes::Bytes;
use courierust::courierust_client::{Client, ClientConfig, TlsSettings as ClientTls};
use courierust::courierust_http::request::Request;
use courierust::courierust_http::response::Response;
use courierust::courierust_server::{Server, ServerConfig, TlsSettings as ServerTls};
use courierust_benchmark::metrics::{
    run_concurrent, run_sequential, stats_fields, report_repetitions, RunMetrics, Timing, MAX_SAMPLES,
};
use std::time::Instant;

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

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
    // P1 parameter matrix: the parent spawns one child process per cell
    // (workers × ack-delay × cwnd). A fresh process per cell is required
    // because the runtime caches the env-derived knobs once per process
    // (they are read on the packet path).
    if std::env::var_os("H3_SWEEP").is_some() && std::env::var_os("H3_SWEEP_CHILD").is_none() {
        sweep_matrix();
        return;
    }
    run_suite();
}

/// Spawn one child bench process per matrix cell. The child inherits
/// stdout, so its `META` + `RESULT` rows (labelled with the cell's env)
/// stream straight into the matrix output.
fn sweep_matrix() {
    use std::process::Command;
    let exe = std::env::current_exe().expect("bench executable path");
    // ACK-delay is a latency/throughput knob; cwnd controls how many
    // ACK-paced rounds a large body takes; workers is the concurrency
    // axis — exactly the P1 matrix dimensions.
    let workers = [1usize, 2, 4, 8, 16];
    let ack_delay_ms = [0u64, 2, 5, 10];
    let cwnds = [2_400usize, 12_000, 48_000];
    let cells = workers.len() * ack_delay_ms.len() * cwnds.len();
    println!(
        "META|suite=h3|sweep=workers_ack_delay_cwnd|cells={cells}|note=one child process per cell"
    );
    for &workers in &workers {
        for &ack_delay_ms in &ack_delay_ms {
            for &cwnd in &cwnds {
                let status = Command::new(&exe)
                    .env("H3_WORKERS", workers.to_string())
                    .env("COURIERUST_H3_ACK_DELAY_MS", ack_delay_ms.to_string())
                    .env("COURIERUST_H3_MIN_ACK_DELAY_MS", ack_delay_ms.to_string())
                    .env("COURIERUST_H3_CWND", cwnd.to_string())
                    .env("H3_SWEEP_CHILD", "1")
                    .status()
                    .expect("spawn sweep child");
                assert!(
                    status.success(),
                    "sweep child failed: workers={workers} ack_delay_ms={ack_delay_ms} cwnd={cwnd}"
                );
            }
        }
    }
}

/// One config cell: cold connect + warm sequential/parallel (+ 64 KiB
/// upload when `BENCH_BODY_BYTES` is set), optionally repeated
/// `BENCH_RUNS` times for cross-run repeatability (P3).
fn run_suite() {
    let requests = env_usize("BENCH_REQUESTS", 1000);
    let workers = env_usize("H3_WORKERS", 8);
    let runs = env_usize("BENCH_RUNS", 1);
    let body_bytes = env_usize("BENCH_BODY_BYTES", 0);

    let ack_delay_ms = std::env::var("COURIERUST_H3_ACK_DELAY_MS")
        .ok()
        .unwrap_or_else(|| "2".to_string());
    let cwnd = std::env::var("COURIERUST_H3_CWND")
        .ok()
        .unwrap_or_else(|| "12000".to_string());
    println!(
        "META|suite=h3|requests={requests}|workers={workers}|runs={runs}|body_bytes={body_bytes}|ack_delay_ms={ack_delay_ms}|cwnd={cwnd}"
    );

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
            ..Default::default()
        }),
        ..Default::default()
    };
    let server = Server::bind_with_config("127.0.0.1:0", server_cfg).unwrap();
    let addr = server.local_addr().unwrap();
    let _handle = server
        .serve_background(|_req: Request<Body>| Response::with_status(200.into()))
        .unwrap();

    let mut roots = courierust::courierust_tls::RootStore::new();
    roots.add_der(CERT_DER.to_vec());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let client_cfg = ClientConfig {
        http3: true,
        // One pooled QUIC connection per authority: the headline number
        // is the warm per-request cost of connection reuse, not a
        // connection-per-worker warm-up artifact.
        max_connections_per_host: 1,
        tls: Some(ClientTls {
            roots,
            verify: true,
            alpn: vec![b"h3".to_vec()],
            now,
            ..Default::default()
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

    // 3. P0: large request-body upload (64 KiB by default when
    //    `BENCH_BODY_BYTES` is set) — the cwnd/ACK-paced transfer the
    //    `COURIERUST_H3_TRACE` packet events dissect. Capped so a slow
    //    cell does not make the matrix take forever.
    if body_bytes > 0 {
        // `Bytes` is an Arc-backed cheap clone; the per-request body is
        // re-wrapped from the same buffer so upload cost is the QUIC
        // transfer, not a per-request allocation.
        let upload_payload = Bytes::from(vec![b'x'; body_bytes]);
        let upload_client = client.clone();
        let upload_url = url.clone();
        let upload_requests = requests.min(200);
        let mut up = run_sequential(upload_requests, MAX_SAMPLES, || {
            let req = Request::post("/upload").with_body(Body::Bytes(upload_payload.clone()));
            let _ = upload_client.execute(&upload_url, req);
        });
        up.sort_samples();
        report("h3_upload", 1, &up);
    }

    // 4. Warm concurrent: workers share the pooled connection(s) and
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

    // P3 cross-run repeatability: re-run sequential + parallel `runs`
    // times and report per-metric mean/min/max/CV (`REPSUM` rows).
    if runs > 1 {
        let mut seq_metrics = Vec::with_capacity(runs);
        let mut conc_metrics = Vec::with_capacity(runs);
        for _ in 0..runs {
            let mut s = run_sequential(requests, MAX_SAMPLES, || {
                let _ = client.get(&url);
            });
            s.sort_samples();
            seq_metrics.push(RunMetrics::from_timing(&s));

            let mut c = run_concurrent(requests, workers, MAX_SAMPLES, |_| {
                let client = client.clone();
                let url = url.clone();
                Box::new(move || {
                    let _ = client.get(&url);
                })
            });
            c.sort_samples();
            conc_metrics.push(RunMetrics::from_timing(&c));
        }
        report_repetitions("h3_sequential", &seq_metrics);
        report_repetitions("h3_parallel", &conc_metrics);
    }
}
