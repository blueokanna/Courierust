//! Cross-machine benchmark endpoint and client.
//!
//! Run one copy as a server on the remote host and one copy as a client on a
//! separate host. The client emits `NETWORK|...` records with the target,
//! protocol, payload, worker count, and latency tail. No loopback result is
//! reported by this binary as cross-machine evidence.

mod metrics;

use courierust::courierust_body::Body;
use courierust::courierust_bytes::Bytes;
use courierust::courierust_client::{Client, ClientConfig, TlsSettings as ClientTls};
use courierust::courierust_http::request::Request;
use courierust::courierust_http::response::Response;
use courierust::courierust_server::{Server, ServerConfig, TlsSettings as ServerTls};
use metrics::{run_concurrent, run_sequential, Timing, MAX_SAMPLES};
use std::sync::Arc;

const DEFAULT_PAYLOAD: usize = 1024;
const DEFAULT_REQUESTS: usize = 1000;

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|v| *v > 0)
        .unwrap_or(default)
}

fn env_bool(name: &str) -> bool {
    matches!(
        std::env::var(name).as_deref(),
        Ok("1") | Ok("true") | Ok("yes") | Ok("on")
    )
}

fn payload() -> Bytes {
    Bytes::from(vec![
        b'x';
        env_usize("COURIERUST_NETWORK_PAYLOAD", DEFAULT_PAYLOAD)
    ])
}

fn load_identity() -> courierust::courierust_tls::Identity {
    let cert_path = std::env::var("COURIERUST_NETWORK_CERT_DER")
        .expect("COURIERUST_NETWORK_CERT_DER is required for TLS server mode");
    let key_path = std::env::var("COURIERUST_NETWORK_KEY_DER")
        .expect("COURIERUST_NETWORK_KEY_DER is required for TLS server mode");
    courierust::courierust_tls::Identity {
        cert_chain: vec![std::fs::read(&cert_path)
            .unwrap_or_else(|e| panic!("read certificate {cert_path}: {e}"))],
        private_key: std::fs::read(&key_path)
            .unwrap_or_else(|e| panic!("read private key {key_path}: {e}")),
        is_rsa: env_bool("COURIERUST_NETWORK_CERT_RSA"),
    }
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn server() -> std::io::Result<()> {
    let bind =
        std::env::var("COURIERUST_NETWORK_BIND").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    let http2 = env_bool("COURIERUST_NETWORK_HTTP2");
    let tls = if env_bool("COURIERUST_NETWORK_TLS") {
        Some(ServerTls {
            identity: load_identity(),
            alpn: if http2 {
                vec![b"h2".to_vec(), b"http/1.1".to_vec()]
            } else {
                vec![b"http/1.1".to_vec()]
            },
        })
    } else {
        None
    };
    let body = payload();
    let server = Server::bind_with_config(
        &bind,
        ServerConfig {
            http2,
            threads: env_usize("COURIERUST_NETWORK_SERVER_THREADS", 4),
            tls,
            ..Default::default()
        },
    )?;
    let address = server.local_addr()?;
    println!(
        "NETWORK|role=server|status=ready|bind={address}|protocol={}|tls={}|payload_bytes={}",
        if http2 { "h2" } else { "h1" },
        env_bool("COURIERUST_NETWORK_TLS"),
        body.len(),
    );
    server.serve(move |_request: Request<Body>| {
        Response::<Body>::with_status(200.into()).with_body(Body::Bytes(body.clone()))
    })
}

fn client() {
    let url = std::env::var("COURIERUST_NETWORK_URL")
        .expect("COURIERUST_NETWORK_URL is required for client mode");
    let protocol =
        std::env::var("COURIERUST_NETWORK_PROTOCOL").unwrap_or_else(|_| "h1".to_string());
    let http2 = matches!(protocol.as_str(), "h2c" | "https-h2" | "h2");
    let workers = env_usize("COURIERUST_NETWORK_WORKERS", 1);
    let requests = env_usize("COURIERUST_NETWORK_REQUESTS", DEFAULT_REQUESTS);
    let expected = env_usize("COURIERUST_NETWORK_PAYLOAD", DEFAULT_PAYLOAD);
    let max_connections = env_usize("COURIERUST_NETWORK_MAX_CONNECTIONS", workers);
    let tls = if url.starts_with("https://") {
        let root_path = std::env::var("COURIERUST_NETWORK_ROOT_DER")
            .expect("COURIERUST_NETWORK_ROOT_DER is required for HTTPS client mode");
        let mut roots = courierust::courierust_tls::RootStore::new();
        roots.add_der(
            std::fs::read(&root_path)
                .unwrap_or_else(|e| panic!("read root certificate {root_path}: {e}")),
        );
        Some(ClientTls {
            roots,
            verify: true,
            alpn: if http2 {
                vec![b"h2".to_vec(), b"http/1.1".to_vec()]
            } else {
                vec![b"http/1.1".to_vec()]
            },
            now: now_unix(),
        })
    } else {
        None
    };
    let client = Arc::new(Client::with_config(ClientConfig {
        http2,
        max_connections_per_host: max_connections,
        tls,
        ..Default::default()
    }));
    let target = Arc::new(url);
    let timing = if workers > 1 {
        run_concurrent(requests, workers, MAX_SAMPLES, |_| {
            let client = client.clone();
            let target = target.clone();
            Box::new(move || network_request(&client, &target, expected))
        })
    } else {
        run_sequential(requests, MAX_SAMPLES, || {
            network_request(&client, &target, expected)
        })
    };
    print_result(
        protocol.as_str(),
        workers,
        max_connections,
        expected,
        timing,
    );
}

fn network_request(client: &Client, target: &str, expected: usize) {
    let response = client.get(target).expect("network request failed");
    assert_eq!(response.status.as_u16(), 200);
    assert_eq!(
        response.body.collect().expect("network body failed").len(),
        expected
    );
}

fn metric(value: Option<f64>) -> String {
    value
        .map(|v| format!("{v:.2}"))
        .unwrap_or_else(|| "na".to_string())
}

fn print_result(
    protocol: &str,
    workers: usize,
    max_connections: usize,
    bytes: usize,
    mut timing: Timing,
) {
    timing.sort_samples();
    println!(
        "NETWORK|role=client|status=ok|target_scope=remote|protocol={protocol}|workers={workers}|max_connections={max_connections}|requests={}|bytes={bytes}|elapsed_ms={:.3}|rps={:.1}|response_mbps={:.3}|p50_us={}|p75_us={}|p90_us={}|p95_us={}|p99_us={}|samples={}",
        timing.requests,
        timing.elapsed.as_secs_f64() * 1000.0,
        timing.requests_per_second(),
        timing.response_megabytes_per_second(bytes),
        metric(timing.percentile_us(0.50)),
        metric(timing.percentile_us(0.75)),
        metric(timing.percentile_us(0.90)),
        metric(timing.percentile_us(0.95)),
        metric(timing.percentile_us(0.99)),
        timing.samples.len(),
    );
}

fn main() {
    match std::env::var("COURIERUST_NETWORK_ROLE").as_deref() {
        Ok("server") => server().expect("network server failed"),
        Ok("client") | Err(_) => client(),
        Ok(other) => panic!("unsupported COURIERUST_NETWORK_ROLE={other}"),
    }
}
