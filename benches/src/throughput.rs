//! Self-contained throughput and latency benchmarks for Courierust.
//!
//! The suite measures the protocol claims that are specific to this crate:
//! HTTP/1.1 keep-alive, HTTP/1.1 worker scaling, HTTP/2 multiplexing, and
//! RFC 9218 priority scheduling. Each case emits a machine-readable result.

mod metrics;

use courierust::body::Body;
use courierust::bytes::Bytes;
use courierust::client::{Client, ClientConfig};
use courierust::h2::priority::Priority;
use courierust::http::request::Request;
use courierust::http::response::Response;
use courierust::server::{Server, ServerConfig};
use metrics::{run_concurrent, run_sequential, Timing, MAX_SAMPLES};
use std::sync::Arc;
use std::time::Instant;

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

fn spawn_server(payload: Bytes, http2: bool, threads: usize) -> std::net::SocketAddr {
    let server = Server::bind_with_config(
        "127.0.0.1:0",
        ServerConfig {
            http2,
            threads,
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
    let response = client.execute(base_url, Request::get(path)).unwrap();
    assert_courierust_response(response, expected_bytes);
}

fn metric(value: Option<f64>) -> String {
    value
        .map(|value| format!("{value:.2}"))
        .unwrap_or_else(|| "na".to_owned())
}

fn print_result(
    case: &str,
    protocol: &str,
    mode: &str,
    payload: Payload,
    workers: usize,
    mut timing: Timing,
) {
    timing.sort_samples();
    println!(
        "RESULT|suite=throughput|case={case}|protocol={protocol}|mode={mode}|payload={}|bytes={}|workers={workers}|requests={}|elapsed_ms={:.3}|rps={:.1}|response_mbps={:.3}|p50_us={}|p75_us={}|p90_us={}|p95_us={}|p99_us={}|samples={}",
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
        timing.samples.len(),
    );
}

fn bench_h1_sequential(payload: Payload, requests: usize, server_threads: usize) {
    let address = spawn_server(payload_bytes(payload), false, server_threads);
    let client = Client::new();
    let base_url = format!("http://{address}");
    courierust_get(&client, &base_url, "/bench", payload.bytes);

    let timing = run_sequential(
        requests,
        MAX_SAMPLES,
        || courierust_get(&client, &base_url, "/bench", payload.bytes),
        || {},
        || 0,
    );
    print_result(
        "h1_sequential",
        "h1",
        "sequential",
        payload,
        1,
        timing,
    );
}

fn bench_h1_parallel(
    payload: Payload,
    requests: usize,
    workers: usize,
    server_threads: usize,
) {
    let address = spawn_server(payload_bytes(payload), false, server_threads);
    let base_url = Arc::new(format!("http://{address}"));
    let clients = Arc::new((0..workers).map(|_| Client::new()).collect::<Vec<_>>());

    for client in clients.iter() {
        courierust_get(client, &base_url, "/bench", payload.bytes);
    }

    let timing = run_concurrent(
        requests,
        workers,
        MAX_SAMPLES,
        |index| {
            let client = clients[index].clone();
            let base_url = base_url.clone();
            Box::new(move || courierust_get(&client, &base_url, "/bench", payload.bytes))
        },
        || {},
        || 0,
    );
    print_result(
        &format!("h1_parallel_w{workers}"),
        "h1",
        "parallel",
        payload,
        workers,
        timing,
    );
}

fn bench_h2_multiplex(
    payload: Payload,
    requests: usize,
    workers: usize,
    server_threads: usize,
) {
    let address = spawn_server(payload_bytes(payload), true, server_threads);
    let base_url = Arc::new(format!("http://{address}"));
    let client = Client::with_config(ClientConfig {
        http2: true,
        max_connections_per_host: 1,
        ..Default::default()
    });
    courierust_get(&client, &base_url, "/bench", payload.bytes);

    let timing = run_concurrent(
        requests,
        workers,
        MAX_SAMPLES,
        |_| {
            let client = client.clone();
            let base_url = base_url.clone();
            Box::new(move || courierust_get(&client, &base_url, "/bench", payload.bytes))
        },
        || {},
        || 0,
    );
    print_result(
        &format!("h2_multiplex_w{workers}"),
        "h2c",
        "multiplex",
        payload,
        workers,
        timing,
    );
}

fn bench_h2_priority(requests: usize, server_threads: usize) {
    let address = spawn_server(Bytes::new(), true, server_threads);
    let client = Client::with_config(ClientConfig {
        http2: true,
        max_connections_per_host: 1,
        ..Default::default()
    });
    let base_url = format!("http://{address}");
    let high = Priority {
        urgency: 0,
        incremental: false,
    };
    let low = Priority {
        urgency: 7,
        incremental: false,
    };
    let request = Request::get("/priority");
    let _ = client
        .execute_priority(&base_url, request.clone(), high)
        .unwrap();

    let rounds = requests.min(32);
    let mut latencies = Vec::with_capacity(rounds);
    let started = Instant::now();
    for _ in 0..rounds {
        let mut low_requests = Vec::with_capacity(32);
        for _ in 0..32 {
            let client = client.clone();
            let base_url = base_url.clone();
            let request = request.clone();
            low_requests.push(std::thread::spawn(move || {
                let _ = client.execute_priority(&base_url, request, low);
            }));
        }

        let high_started = Instant::now();
        let response = client
            .execute_priority(&base_url, request.clone(), high)
            .unwrap();
        assert_eq!(response.status.as_u16(), 200);
        latencies.push(high_started.elapsed());

        for worker in low_requests {
            worker.join().unwrap();
        }
    }

    let timing = Timing {
        elapsed: started.elapsed(),
        requests: rounds,
        samples: latencies,
        allocations: 0,
    };
    print_result(
        "h2_priority_high_latency",
        "h2c",
        "priority",
        EMPTY,
        32,
        timing,
    );
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

    bench_h2_priority(requests, server_threads);
    println!("total: complete");
}
