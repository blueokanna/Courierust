//! Self-contained throughput and latency benchmarks for Courierust.
//!
//! The suite measures the protocol claims that are specific to this crate:
//! HTTP/1.1 keep-alive, HTTP/1.1 worker scaling, HTTP/2 multiplexing, and
//! end-to-end HTTPS plus HTTP/2. Each case emits a machine-readable result.

use courierust::courierust_body::Body;
use courierust::courierust_bytes::Bytes;
use courierust::courierust_client::{Client, ClientConfig};
use courierust::courierust_http::request::Request;
use courierust::courierust_http::response::Response;
use courierust::courierust_net::stats::Stats;
use courierust::courierust_server::{Server, ServerConfig};
use courierust::courierust_tls as crate_tls;
use courierust_benchmark::metrics::{metric, run_concurrent, run_sequential, stats_fields, Timing, MAX_SAMPLES};
use std::sync::Arc;

const EMPTY: Payload = Payload {
    name: "empty",
    bytes: 0,
};
const ONE_KIB: Payload = Payload {
    name: "1k",
    bytes: 1024,
};
const SIXTY_FOUR_KIB: Payload = Payload {
    name: "64k",
    bytes: 64 * 1024,
};

#[derive(Clone, Copy)]
struct Payload {
    name: &'static str,
    bytes: usize,
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

fn payload_bytes(payload: Payload) -> Bytes {
    if payload.bytes == 0 {
        Bytes::new()
    } else {
        Bytes::from(vec![b'x'; payload.bytes])
    }
}

fn spawn_server(
    payload: Bytes,
    http2: bool,
    threads: usize,
    stats: Option<std::sync::Arc<courierust::courierust_net::stats::Stats>>,
) -> std::net::SocketAddr {
    let server = Server::bind_with_config(
        "127.0.0.1:0",
        ServerConfig {
            http2,
            threads,
            stats,
            ..Default::default()
        },
    )
    .unwrap();
    let address = server.local_addr().unwrap();
    let handle = server
        .serve_background(move |_request: Request<Body>| {
            Response::<Body>::with_status(200.into()).with_body(Body::Bytes(payload.clone()))
        })
        .unwrap();
    std::mem::forget(handle);
    address
}

fn assert_courierust_response(response: Response<Body>, expected_bytes: usize) {
    assert_eq!(response.status.as_u16(), 200);
    assert_eq!(response.body.collect().unwrap().len(), expected_bytes);
}

fn courierust_get(client: &Client, base_url: &str, path: &str, expected_bytes: usize) {
    let pq = courierust::courierust_http::uri::PathAndQuery::from_bytes(path.as_bytes()).unwrap();
    let req = courierust::courierust_http::request::Request::get(pq).with_body(Body::Empty);
    let response = client.execute(base_url, req).unwrap();
    assert_courierust_response(response, expected_bytes);
}

fn print_result(
    case: &str,
    protocol: &str,
    mode: &str,
    payload: Payload,
    workers: usize,
    server_threads: usize,
    mut timing: Timing,
) {
    timing.sort_samples();
    println!(
        "RESULT|suite=throughput|case={case}|protocol={protocol}|mode={mode}|payload={}|bytes={}|workers={workers}|server_threads={server_threads}|requests={}|elapsed_ms={:.3}|rps={:.1}|response_mbps={:.3}|p50_us={}|p75_us={}|p90_us={}|p95_us={}|p99_us={}|{}|samples={}",
        payload.name,
        payload.bytes,
        timing.requests,
        timing.elapsed.as_secs_f64() * 1000.0,
        timing.requests_per_second(),
        timing.response_megabytes_per_second(payload.bytes),
        metric(timing.percentile_us(0.50)),
        metric(timing.percentile_us(0.75)),
        metric(timing.percentile_us(0.90)),
        metric(timing.percentile_us(0.95)),
        metric(timing.percentile_us(0.99)),
        stats_fields(&timing),
        timing.samples.len(),
    );
}

fn bench_h1_sequential(payload: Payload, requests: usize, server_threads: usize) {
    let address = spawn_server(payload_bytes(payload), false, server_threads, None);
    let client = Client::new();
    let base_url = format!("http://{address}");
    courierust_get(&client, &base_url, "/bench", payload.bytes);

    let timing = run_sequential(requests, MAX_SAMPLES, || {
        courierust_get(&client, &base_url, "/bench", payload.bytes)
    });
    print_result(
        "h1_sequential",
        "h1",
        "sequential",
        payload,
        1,
        server_threads,
        timing,
    );
}

fn bench_h1_parallel(payload: Payload, requests: usize, workers: usize, server_threads: usize) {
    // On blocking server platforms, one idle keep-alive connection occupies
    // one server worker. Keep enough workers for the client herd or the
    // sequential warm-up below can deadlock before measurement starts.
    let server_threads = server_threads.max(workers);
    let address = spawn_server(payload_bytes(payload), false, server_threads, None);
    let base_url = Arc::new(format!("http://{address}"));
    let clients = Arc::new((0..workers).map(|_| Client::new()).collect::<Vec<_>>());

    for client in clients.iter() {
        courierust_get(client, &base_url, "/bench", payload.bytes);
    }

    let timing = run_concurrent(requests, workers, MAX_SAMPLES, |index| {
        let client = clients[index].clone();
        let base_url = base_url.clone();
        Box::new(move || courierust_get(&client, &base_url, "/bench", payload.bytes))
    });
    print_result(
        &format!("h1_parallel_w{workers}"),
        "h1",
        "parallel",
        payload,
        workers,
        server_threads,
        timing,
    );
}

/// Emit the reactor/connection/stream evidence collected for one case.
fn print_stats(protocol: &str, case: &str, payload: Payload, workers: usize, stats: &Stats) {
    println!(
        "STATS|suite=throughput|protocol={protocol}|case={case}|payload={}|workers={workers}|{}",
        payload.name,
        stats.snapshot().render(),
    );
}

fn bench_h2_multiplex(payload: Payload, requests: usize, workers: usize, server_threads: usize) {
    // Instrument both ends so the >8-worker h2 regression is diagnosable:
    // a 1-connection multiplex shows `h2_connections=1` with `workers`
    // concurrent streams (the single-driver serialization point).
    let server_stats = Stats::new();
    let client_stats = Stats::new();
    let address = spawn_server(
        payload_bytes(payload),
        true,
        server_threads,
        Some(server_stats.clone()),
    );
    let base_url = Arc::new(format!("http://{address}"));
    let client = Client::with_config(ClientConfig {
        http2: true,
        max_connections_per_host: 1,
        stats: Some(client_stats.clone()),
        ..Default::default()
    });
    courierust_get(&client, &base_url, "/bench", payload.bytes);

    let timing = run_concurrent(requests, workers, MAX_SAMPLES, |_| {
        let client = client.clone();
        let base_url = base_url.clone();
        Box::new(move || courierust_get(&client, &base_url, "/bench", payload.bytes))
    });
    print_result(
        &format!("h2_multiplex_w{workers}"),
        "h2c",
        "multiplex",
        payload,
        workers,
        server_threads,
        timing,
    );
    print_stats(
        "h2c",
        &format!("h2_multiplex_w{workers}"),
        payload,
        workers,
        &server_stats,
    );
    print_stats(
        "h2c",
        &format!("h2_multiplex_w{workers}"),
        payload,
        workers,
        &client_stats,
    );
}

/// Load the test identity (self-signed Ed25519, CN=localhost) and return
/// it. The DER files live under `tests/certs/` and are compiled in, so
/// the binary runs from any working directory.
const SERVER_CERT_DER: &[u8] = include_bytes!("../../tests/certs/server_cert.der");
const SERVER_KEY_DER: &[u8] = include_bytes!("../../tests/certs/server_key.der");

fn load_test_identity() -> (crate_tls::Identity, crate_tls::RootStore) {
    let identity = crate_tls::Identity {
        cert_chain: vec![SERVER_CERT_DER.to_vec()],
        private_key: SERVER_KEY_DER.to_vec(),
        is_rsa: false,
    };
    let mut roots = crate_tls::RootStore::new();
    roots.add_der(SERVER_CERT_DER.to_vec());
    (identity, roots)
}

/// HTTPS (TLS 1.3 plus h2) throughput and latency through the crate's TLS
/// stack, covering the path that a loopback h2c benchmark cannot measure.
fn bench_https(requests: usize, payload: Payload, server_threads: usize) {
    use courierust::courierust_client::TlsSettings as ClientTls;
    use courierust::courierust_server::TlsSettings as ServerTls;

    let (identity, roots) = load_test_identity();
    let body = payload_bytes(payload);
    let server = Server::bind_with_config(
        "127.0.0.1:0",
        ServerConfig {
            http2: true,
            threads: server_threads,
            tls: Some(ServerTls {
                identity,
                alpn: vec![b"h2".to_vec()],
            }),
            ..Default::default()
        },
    )
    .unwrap();
    let address = server.local_addr().unwrap();
    let handle = server
        .serve_background(move |_request: Request<Body>| {
            Response::<Body>::with_status(200.into()).with_body(Body::Bytes(body.clone()))
        })
        .unwrap();
    std::mem::forget(handle);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let client = Client::with_config(ClientConfig {
        http2: true,
        max_connections_per_host: 1,
        tls: Some(ClientTls {
            roots: roots.clone(),
            verify: true,
            alpn: vec![b"h2".to_vec()],
            now,
            ..Default::default()
        }),
        ..Default::default()
    });
    let base_url = format!("https://{address}");
    courierust_get(&client, &base_url, "/bench", payload.bytes);

    let timing = run_sequential(requests, MAX_SAMPLES, || {
        courierust_get(&client, &base_url, "/bench", payload.bytes)
    });
    print_result(
        "https_h2_sequential",
        "https+h2",
        "sequential",
        payload,
        1,
        server_threads,
        timing,
    );
    tls_verify_evidence(address, roots);
}

/// TLS evidence behind an HTTPS row: cert + hostname verified (else the
/// handshake would fail), negotiated ALPN + cipher suite as observed on the
/// wire. session_resumption=n/a: a single handshake does not measure it.
fn tls_verify_evidence(address: std::net::SocketAddr, roots: crate_tls::RootStore) {
    use courierust::courierust_tls::{
        ClientConfig as TlsClientConfig, TlsConnector, TlsVersion,
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let stream = std::net::TcpStream::connect(address);
    let stream = match stream {
        Ok(s) => s,
        Err(e) => {
            println!(
                "TLSVERIFY|protocol=https+h2|cert_verified=false|hostname_verified=false|error=connect:{}",
                e.to_string().replace('|', "/")
            );
            return;
        }
    };
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(5)));
    let connector = TlsConnector::new(TlsClientConfig {
        roots,
        verify: true,
        alpn: vec![b"h2".to_vec()],
        now,
        min_version: TlsVersion::Tls12,
        max_version: TlsVersion::Tls13,
    });
    match connector.connect("127.0.0.1", &stream, &stream) {
        Ok(tls) => {
            let negotiated = tls
                .alpn()
                .map(|a| String::from_utf8_lossy(a).into_owned())
                .unwrap_or_else(|| "none".to_string());
            println!(
                "TLSVERIFY|protocol=https+h2|cert_verified=true|hostname_verified=true|negotiated_alpn={negotiated}|session_resumption=n/a|cipher_suite=0x{:04x}",
                tls.cipher_suite()
            );
        }
        Err(e) => println!(
            "TLSVERIFY|protocol=https+h2|cert_verified=false|hostname_verified=false|error={}",
            e.to_string().replace('|', "/")
        ),
    }
}

fn main() {
    let requests = env_usize("BENCH_REQUESTS", 4_000);
    let server_threads = env_usize("BENCH_SERVER_THREADS", 4);
    println!("courierust throughput suite (loopback)");
    println!(
        "META|suite=throughput|requests={requests}|server_threads={server_threads}|max_samples={MAX_SAMPLES}"
    );

    for payload in [EMPTY, ONE_KIB, SIXTY_FOUR_KIB] {
        bench_h1_sequential(payload, requests, server_threads);
    }

    for workers in [1, 4, 8] {
        if workers <= requests {
            bench_h1_parallel(ONE_KIB, requests, workers, server_threads);
        }
    }

    for payload in [ONE_KIB, SIXTY_FOUR_KIB] {
        for workers in [1, 8, 32] {
            if workers <= requests {
                bench_h2_multiplex(payload, requests, workers, server_threads);
            }
        }
    }

    for payload in [EMPTY, ONE_KIB, SIXTY_FOUR_KIB] {
        bench_https(requests.min(2000), payload, server_threads);
    }

    println!("total: complete");
}
