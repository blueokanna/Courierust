//! Fair loopback comparison against hyper and reqwest.
//!
//! Every row changes one side of the connection at a time. Client rows use
//! the same hyper server; server rows use the same reqwest client. HTTP/1.1
//! and h2c run independently, and response bodies are fully consumed before
//! a request is counted as complete.

use bytes::Buf;
use courierust::courierust_body::Body;
use courierust::courierust_bytes::Bytes;
use courierust::courierust_client::{Client, ClientConfig};
use courierust::courierust_http::request::Request;
use courierust::courierust_http::response::Response;
use courierust::courierust_server::{Server, ServerConfig, TlsSettings as ServerTls};
use courierust_benchmark::metrics::{run_concurrent, run_sequential, Timing, MAX_SAMPLES};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;

const H3_CERT_DER: &[u8] = include_bytes!("../../tests/certs/server_cert.der");
const H3_KEY_DER: &[u8] = include_bytes!("../../tests/certs/server_key.der");

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

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

struct ResultMetadata {
    case: &'static str,
    layer: &'static str,
    protocol: Protocol,
    client: &'static str,
    server: &'static str,
    payload: Payload,
    workers: usize,
    repetitions: usize,
    server_threads: usize,
    pool_policy: &'static str,
    pool_value: usize,
}

#[derive(Clone, Copy)]
enum Protocol {
    H1,
    H2c,
    H3,
}

impl Protocol {
    fn name(self) -> &'static str {
        match self {
            Self::H1 => "h1",
            Self::H2c => "h2c",
            Self::H3 => "h3",
        }
    }

    fn uses_http2(self) -> bool {
        matches!(self, Self::H2c)
    }
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

fn comparison_repetitions() -> usize {
    let requested = env_usize("BENCH_REPETITIONS", 2);
    if requested.is_multiple_of(2) {
        requested
    } else {
        requested.checked_add(1).unwrap_or(requested - 1)
    }
}

fn response_bytes(payload: Payload) -> Bytes {
    Bytes::from(vec![b'x'; payload.bytes])
}

/// Bind a Courierust server that serves `payload` on every request and
/// leak its shutdown handle so it outlives the bench process.
fn serve_courierust(config: ServerConfig, payload: Payload) -> SocketAddr {
    let server = Server::bind_with_config("127.0.0.1:0", config).unwrap();
    let address = server.local_addr().unwrap();
    let body = response_bytes(payload);
    let handle = server
        .serve_background(move |_request: Request<Body>| {
            Response::<Body>::with_status(200.into()).with_body(Body::Bytes(body.clone()))
        })
        .unwrap();
    std::mem::forget(handle);
    address
}

fn courierust_server(protocol: Protocol, payload: Payload) -> SocketAddr {
    serve_courierust(
        ServerConfig {
            http2: protocol.uses_http2(),
            threads: 4,
            ..Default::default()
        },
        payload,
    )
}

fn hyper_server(protocol: Protocol, payload: Payload) -> SocketAddr {
    use http_body_util::{BodyExt, Full};
    use hyper::body::{Bytes as HyperBytes, Incoming};
    use hyper::service::service_fn;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::server::conn::auto::Builder as AutoBuilder;
    use std::convert::Infallible;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    let listener = runtime
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .unwrap();
    let address = listener.local_addr().unwrap();
    let body = HyperBytes::from(response_bytes(payload).to_vec());

    std::thread::spawn(move || {
        runtime.block_on(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                // Fair loopback comparison: the Courierust server and
                // every client set TCP_NODELAY; hyper's auto builder does
                // not, and without it the 64 KiB rows stall ~40 ms per
                // request (Linux delayed-ACK + Nagle) for no protocol
                // reason.
                let _ = stream.set_nodelay(true);
                let body = body.clone();
                let service = service_fn(move |request: hyper::Request<Incoming>| {
                    let body = body.clone();
                    async move {
                        // Consume uploads so the h2 flow-control window is
                        // exercised and a large-body comparison cannot pass
                        // merely because the peer discarded the request.
                        let _ = BodyExt::collect(request.into_body()).await;
                        Ok::<_, Infallible>(hyper::Response::new(Full::new(body)))
                    }
                });
                let builder = match protocol {
                    Protocol::H1 => AutoBuilder::new(TokioExecutor::new()).http1_only(),
                    Protocol::H2c => AutoBuilder::new(TokioExecutor::new()).http2_only(),
                    Protocol::H3 => unreachable!("H3 uses the Courierust H3 server"),
                };
                tokio::spawn(async move {
                    let _ = builder
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
    });
    address
}

fn assert_courierust_response(response: Response<Body>, expected_bytes: usize) {
    assert_eq!(response.status.as_u16(), 200);
    assert_eq!(response.body.collect().unwrap().len(), expected_bytes);
}

fn run_courierust_client(
    protocol: Protocol,
    address: SocketAddr,
    payload: Payload,
    requests: usize,
    workers: usize,
) -> Timing {
    let client = Client::with_config(ClientConfig {
        http2: protocol.uses_http2(),
        max_connections_per_host: workers.max(1),
        ..Default::default()
    });
    let url = format!("http://{address}/benchmark");
    assert_courierust_response(client.get(&url).unwrap(), payload.bytes);

    if workers == 1 {
        run_sequential(requests, MAX_SAMPLES, || {
            assert_courierust_response(client.get(&url).unwrap(), payload.bytes);
        })
    } else {
        run_concurrent(requests, workers, MAX_SAMPLES, |_| {
            let client = client.clone();
            let url = url.clone();
            Box::new(move || {
                assert_courierust_response(client.get(&url).unwrap(), payload.bytes);
            })
        })
    }
}

/// A valid mainstream-client baseline. HTTP/1.1 uses reqwest's blocking
/// client (a plain, fair comparison for keep-alive h1). HTTP/2 prior
/// knowledge uses the *async* reqwest client driven through a tokio
/// multi-thread runtime.
///
/// Pool semantics differ between the two clients and must not be
/// conflated: Courierust's `max_connections_per_host` is a cap on *live*
/// connections per authority, while reqwest's `pool_max_idle_per_host`
/// is a cap on *idle pooled* connections. Setting both to the same value
/// N is only equivalent for a sequential workload; under concurrency
/// reqwest may open more live connections than N (it recycles up to N
/// idle ones).
enum ReqwestClient {
    Blocking(reqwest::blocking::Client),
    Async(Arc<reqwest::Client>),
}

fn reqwest_client(protocol: Protocol, workers: usize) -> ReqwestClient {
    if protocol.uses_http2() {
        let builder = reqwest::Client::builder().pool_max_idle_per_host(workers);
        ReqwestClient::Async(Arc::new(builder.http2_prior_knowledge().build().unwrap()))
    } else {
        let builder = reqwest::blocking::Client::builder().pool_max_idle_per_host(workers);
        ReqwestClient::Blocking(builder.build().unwrap())
    }
}

fn assert_reqwest_response(
    response: reqwest::Response,
    expected_bytes: usize,
    handle: &tokio::runtime::Handle,
) {
    assert_eq!(response.status().as_u16(), 200);
    let body = handle.block_on(response.bytes()).unwrap();
    assert_eq!(body.len(), expected_bytes);
}

fn assert_reqwest_blocking_response(response: reqwest::blocking::Response, expected_bytes: usize) {
    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(response.bytes().unwrap().len(), expected_bytes);
}

fn run_reqwest_client(
    protocol: Protocol,
    address: SocketAddr,
    payload: Payload,
    requests: usize,
    workers: usize,
    handle: &tokio::runtime::Handle,
) -> Timing {
    let expected = payload.bytes;
    match reqwest_client(protocol, workers) {
        ReqwestClient::Blocking(client) => {
            let url = format!("http://{address}/benchmark");
            assert_reqwest_blocking_response(client.get(&url).send().unwrap(), expected);
            if workers == 1 {
                run_sequential(requests, MAX_SAMPLES, || {
                    assert_reqwest_blocking_response(client.get(&url).send().unwrap(), expected);
                })
            } else {
                run_concurrent(requests, workers, MAX_SAMPLES, |_| {
                    let client = client.clone();
                    let url = url.clone();
                    Box::new(move || {
                        assert_reqwest_blocking_response(
                            client.get(&url).send().unwrap(),
                            expected,
                        );
                    })
                })
            }
        }
        ReqwestClient::Async(client) => {
            let url = format!("http://{address}/benchmark");
            let handle = handle.clone();
            assert_reqwest_response(
                handle.block_on(client.get(&url).send()).unwrap(),
                expected,
                &handle,
            );
            if workers == 1 {
                run_sequential(requests, MAX_SAMPLES, || {
                    let url = url.clone();
                    assert_reqwest_response(
                        handle.block_on(client.get(&url).send()).unwrap(),
                        expected,
                        &handle,
                    );
                })
            } else {
                run_concurrent(requests, workers, MAX_SAMPLES, |_| {
                    let client = client.clone();
                    let url = url.clone();
                    let handle = handle.clone();
                    Box::new(move || {
                        assert_reqwest_response(
                            handle.block_on(client.get(&url).send()).unwrap(),
                            expected,
                            &handle,
                        );
                    })
                })
            }
        }
    }
}

fn large_h2_body() -> Vec<u8> {
    let bytes = env_usize("BENCH_H2_LARGE_BODY_BYTES", 1024 * 1024);
    (0..bytes).map(|index| (index % 251) as u8).collect()
}

fn run_courierust_h2_large_body(
    address: SocketAddr,
    response_payload: Payload,
    request_body: &[u8],
    requests: usize,
) -> Timing {
    let client = Client::with_config(ClientConfig {
        http2: true,
        max_connections_per_host: 1,
        ..Default::default()
    });
    let url = format!("http://{address}/large-body");
    let request = || {
        let req =
            Request::post("/large-body").with_body(Body::Bytes(Bytes::from(request_body.to_vec())));
        assert_courierust_response(client.execute(&url, req).unwrap(), response_payload.bytes);
    };
    request();
    run_sequential(requests, MAX_SAMPLES, request)
}

fn run_reqwest_h2_large_body(
    address: SocketAddr,
    response_payload: Payload,
    request_body: &[u8],
    requests: usize,
    handle: &tokio::runtime::Handle,
) -> Timing {
    let client = Arc::new(
        reqwest::Client::builder()
            .http2_prior_knowledge()
            .pool_max_idle_per_host(1)
            .build()
            .unwrap(),
    );
    let url = format!("http://{address}/large-body");
    let send = || {
        let client = client.clone();
        let url = url.clone();
        let body = request_body.to_vec();
        let response =
            handle.block_on(async move { client.post(url).body(body).send().await.unwrap() });
        assert_reqwest_response(response, response_payload.bytes, handle);
    };
    send();
    run_sequential(requests, MAX_SAMPLES, send)
}

fn compare_h2_large_body(
    address: SocketAddr,
    response_payload: Payload,
    requests: usize,
    repetitions: usize,
    handle: &tokio::runtime::Handle,
) {
    // Both clients face the SAME hyper h2 server's 64 KiB initial
    // flow-control window: every 64 KiB of the 1 MiB request body needs
    // a WINDOW_UPDATE round trip, so absolute per-request cost is pacing,
    // not either client's core path. Kept for auditability; NOT valid for
    // ratio claims — the fixed wait persists with the async client, so
    // the "blocking-client artifact" framing was wrong.
    let request_body = large_h2_body();
    let (courierust_timing, reqwest_timing) = measure_pair(
        repetitions,
        || run_courierust_h2_large_body(address, response_payload, &request_body, requests),
        || run_reqwest_h2_large_body(address, response_payload, &request_body, requests, handle),
    );
    print_result(
        ResultMetadata {
            case: "courierust_h2c_large_body_to_hyper",
            layer: "client",
            protocol: Protocol::H2c,
            client: "courierust",
            server: "hyper",
            payload: response_payload,
            workers: 1,
            repetitions,
            server_threads: 4,
            pool_policy: "courierust_max_connections_per_host",
            pool_value: 1,
        },
        courierust_timing,
    );
    print_result(
        ResultMetadata {
            case: "reqwest_async_h2c_large_body_to_hyper",
            layer: "client",
            protocol: Protocol::H2c,
            client: "reqwest-async",
            server: "hyper",
            payload: response_payload,
            workers: 1,
            repetitions,
            server_threads: 4,
            pool_policy: "reqwest_pool_max_idle_per_host",
            pool_value: 1,
        },
        reqwest_timing,
    );
}

fn metric(value: Option<f64>) -> String {
    value
        .map(|value| format!("{value:.2}"))
        .unwrap_or_else(|| "na".to_owned())
}

fn print_result(metadata: ResultMetadata, mut timing: Timing) {
    let ResultMetadata {
        case,
        layer,
        protocol,
        client,
        server,
        payload,
        workers,
        repetitions,
        server_threads,
        pool_policy,
        pool_value,
    } = metadata;
    timing.sort_samples();
    println!(
        "RESULT|suite=compare|case={case}|layer={layer}|protocol={}|client={client}|server={server}|payload={}|bytes={}|workers={workers}|server_threads={server_threads}|pool_policy={pool_policy}|pool_value={pool_value}|repetitions={repetitions}|status=valid|reason=-|requests={}|elapsed_ms={:.3}|rps={:.1}|response_mbps={:.3}|p50_us={}|p75_us={}|p90_us={}|p95_us={}|p99_us={}|samples={}",
        protocol.name(),
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

fn merge_timing(total: &mut Option<Timing>, timing: Timing) {
    if let Some(total) = total {
        total.elapsed += timing.elapsed;
        total.requests += timing.requests;
        total.samples.extend(timing.samples);
    } else {
        *total = Some(timing);
    }
}

/// Execute both sides in alternating order. `repetitions` is always even,
/// so each side runs first equally often and setup/cache effects do not
/// consistently favor one implementation.
fn measure_pair<First, Second>(repetitions: usize, first: First, second: Second) -> (Timing, Timing)
where
    First: Fn() -> Timing,
    Second: Fn() -> Timing,
{
    let mut first_total = None;
    let mut second_total = None;

    for iteration in 0..repetitions {
        if iteration % 2 == 0 {
            merge_timing(&mut first_total, first());
            merge_timing(&mut second_total, second());
        } else {
            merge_timing(&mut second_total, second());
            merge_timing(&mut first_total, first());
        }
    }

    (
        first_total.expect("comparison repetitions must be positive"),
        second_total.expect("comparison repetitions must be positive"),
    )
}

fn raw_tcp_floor(requests: usize) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let worker = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buffer = [0u8; 4096];
        loop {
            match stream.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(read) => {
                    if stream.write_all(&buffer[..read]).is_err() {
                        break;
                    }
                }
            }
        }
    });
    let mut stream = TcpStream::connect(address).unwrap();
    stream.set_nodelay(true).unwrap();
    stream.write_all(b"warm").unwrap();
    let mut warm = [0u8; 4];
    stream.read_exact(&mut warm).unwrap();

    let timing = run_sequential(requests, MAX_SAMPLES, || {
        stream.write_all(b"ping").unwrap();
        let mut response = [0u8; 4];
        stream.read_exact(&mut response).unwrap();
        assert_eq!(&response, b"ping");
    });
    print_result(
        ResultMetadata {
            case: "raw_tcp_floor",
            layer: "transport",
            protocol: Protocol::H1,
            client: "std_tcp",
            server: "std_tcp",
            payload: Payload {
                name: "4b",
                bytes: 4,
            },
            workers: 1,
            repetitions: 1,
            server_threads: 1,
            pool_policy: "raw_tcp",
            pool_value: 1,
        },
        timing,
    );
    drop(stream);
    worker.join().unwrap();
}

fn compare_clients(
    protocol: Protocol,
    address: SocketAddr,
    payload: Payload,
    requests: usize,
    workers: usize,
    repetitions: usize,
    handle: &tokio::runtime::Handle,
) {
    let (courierust_timing, reqwest_timing) = measure_pair(
        repetitions,
        || run_courierust_client(protocol, address, payload, requests, workers),
        || run_reqwest_client(protocol, address, payload, requests, workers, handle),
    );
    print_result(
        ResultMetadata {
            case: "courierust_client_to_hyper",
            layer: "client",
            protocol,
            client: "courierust",
            server: "hyper",
            payload,
            workers,
            repetitions,
            server_threads: 4,
            pool_policy: "courierust_max_connections_per_host",
            pool_value: workers.max(1),
        },
        courierust_timing,
    );

    print_result(
        ResultMetadata {
            case: "reqwest_client_to_hyper",
            layer: "client",
            protocol,
            client: "reqwest",
            server: "hyper",
            payload,
            workers,
            repetitions,
            server_threads: 4,
            pool_policy: "reqwest_pool_max_idle_per_host",
            pool_value: workers.max(1),
        },
        reqwest_timing,
    );
}

fn compare_servers(
    protocol: Protocol,
    courierust: SocketAddr,
    hyper: SocketAddr,
    payload: Payload,
    requests: usize,
    repetitions: usize,
    handle: &tokio::runtime::Handle,
) {
    let (courierust_timing, hyper_timing) = measure_pair(
        repetitions,
        || run_reqwest_client(protocol, courierust, payload, requests, 1, handle),
        || run_reqwest_client(protocol, hyper, payload, requests, 1, handle),
    );
    print_result(
        ResultMetadata {
            case: "reqwest_client_to_courierust",
            layer: "server",
            protocol,
            client: "reqwest",
            server: "courierust",
            payload,
            workers: 1,
            repetitions,
            server_threads: 4,
            pool_policy: "reqwest_pool_max_idle_per_host",
            pool_value: 1,
        },
        courierust_timing,
    );

    print_result(
        ResultMetadata {
            case: "reqwest_client_to_hyper",
            layer: "server",
            protocol,
            client: "reqwest",
            server: "hyper",
            payload,
            workers: 1,
            repetitions,
            server_threads: 4,
            pool_policy: "reqwest_pool_max_idle_per_host",
            pool_value: 1,
        },
        hyper_timing,
    );
}

// ---------------------------------------------------------------------
// HTTP/3 (QUIC v1 + TLS 1.3): Courierust H3 client vs quinn + h3 crate
// against the SAME Courierust H3 server. Both reuse one pooled QUIC
// connection, so rows are warm per-request cost.
// ---------------------------------------------------------------------

/// A Courierust HTTP/3 (QUIC v1 + TLS 1.3, ALPN `h3`) server.
fn h3_server(payload: Payload) -> SocketAddr {
    let identity = courierust::courierust_tls::Identity {
        cert_chain: vec![H3_CERT_DER.to_vec()],
        private_key: H3_KEY_DER.to_vec(),
        is_rsa: false,
    };
    serve_courierust(
        ServerConfig {
            http3: true,
            tls: Some(ServerTls {
                identity,
                alpn: vec![b"h3".to_vec()],
            }),
            threads: 4,
            ..Default::default()
        },
        payload,
    )
}

fn run_courierust_h3_client(address: SocketAddr, payload: Payload, requests: usize) -> Timing {
    let mut roots = courierust::courierust_tls::RootStore::new();
    roots.add_der(H3_CERT_DER.to_vec());
    let client = Client::with_config(ClientConfig {
        http3: true,
        max_connections_per_host: 1,
        read_timeout: Some(std::time::Duration::from_secs(10)),
        tls: Some(courierust::courierust_client::TlsSettings {
            roots,
            verify: true,
            alpn: vec![b"h3".to_vec()],
            now: unix_now(),
        }),
        ..Default::default()
    });
    let url = format!("https://{address}/benchmark");
    let request = || {
        let response = client.get(&url).unwrap();
        assert_eq!(response.body.collect().unwrap().len(), payload.bytes);
    };
    request();
    run_sequential(requests, MAX_SAMPLES, request)
}

/// quinn + h3 crate client: one long-lived QUIC connection, every
/// request a fresh H3 stream on it (the same reuse model as the
/// Courierust pool). 0-RTT/early-data is explicitly disabled.
///
/// Returns an `Err(reason)` when the independent QUIC/TLS handshake does
/// not complete against the Courierust server — a genuine interop gap
/// that is reported (never silently skipped or faked).
fn run_quinn_h3_client(
    address: SocketAddr,
    payload: Payload,
    requests: usize,
    handle: &tokio::runtime::Handle,
) -> Result<Timing, String> {
    let _ = rustls::crypto::CryptoProvider::install_default(
        rustls::crypto::aws_lc_rs::default_provider(),
    );

    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(
            H3_CERT_DER.to_vec(),
        ))
        .expect("test cert parses");
    let mut crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    crypto.alpn_protocols = vec![b"h3".to_vec()];
    crypto.enable_early_data = false;
    let quic_crypto =
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto).expect("rustls config");

    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        std::time::Duration::from_secs(5)
            .try_into()
            .expect("valid idle timeout"),
    ));
    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_crypto));
    client_config.transport_config(Arc::new(transport));

    let (_endpoint, mut h3_conn, mut send_request) = handle.block_on(async move {
        let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(client_config);
        let connecting = endpoint
            .connect(address, "localhost")
            .expect("quinn connect starts");
        let connection = connecting
            .await
            .map_err(|e| format!("quinn handshake: {e:?}"))?;
        let (h3_conn, send_request) = h3::client::builder()
            .build::<_, _, bytes::Bytes>(h3_quinn::Connection::new(connection))
            .await
            .map_err(|e| format!("h3 connect: {e:?}"))?;
        Ok::<_, String>((endpoint, h3_conn, send_request))
    })?;
    // wait_idle drives the connection until it closes; Handle::spawn
    // works off a runtime context, tokio::spawn would panic here.
    handle.spawn(async move {
        let _ = h3_conn.wait_idle().await;
    });

    let uri = format!("https://{address}/benchmark");
    let request = |send_request: &mut h3::client::SendRequest<_, _>| {
        let req = http::Request::builder()
            .uri(&uri)
            .body(())
            .expect("request built");
        let mut stream = handle
            .block_on(send_request.send_request(req))
            .expect("send request");
        handle.block_on(stream.finish()).expect("finish request");
        let response = handle.block_on(stream.recv_response()).expect("response");
        assert_eq!(response.status().as_u16(), 200);
        let mut total = 0usize;
        while let Some(chunk) = handle.block_on(stream.recv_data()).expect("recv data") {
            total += chunk.remaining();
        }
        assert_eq!(total, payload.bytes);
    };
    request(&mut send_request);
    Ok(run_sequential(requests, MAX_SAMPLES, || {
        request(&mut send_request)
    }))
}

fn print_quinn_not_available(payload: Payload, repetitions: usize, reason: String) {
    println!(
        "RESULT|suite=compare|case=quinn_h3_client_to_courierust|layer=client|protocol=h3|client=quinn+h3|server=courierust-h3|payload={}|bytes={}|workers=1|server_threads=4|pool_policy=quinn_single_connection|pool_value=1|repetitions={repetitions}|status=not_available|reason=quinn_handshake_interop_pending:{reason}|requests=0|elapsed_ms=0|rps=0|response_mbps=0|p50_us=na|p75_us=na|p90_us=na|p95_us=na|p99_us=na|samples=0",
        payload.name, payload.bytes
    );
}

fn compare_h3_clients(
    payload: Payload,
    requests: usize,
    repetitions: usize,
    handle: &tokio::runtime::Handle,
) {
    let address = h3_server(payload);
    let mut courierust_timing = None;
    for _ in 0..repetitions {
        merge_timing(
            &mut courierust_timing,
            run_courierust_h3_client(address, payload, requests),
        );
    }
    let courierust_timing = courierust_timing.expect("repetitions positive");

    // Probe the independent handshake once. A failure is reported as
    // `not_available` and skipped — repeating a known-failing handshake
    // would only burn CI time on 5 s idle timeouts. A failure after a
    // successful probe is a real regression and fails the bench.
    let mut quinn_timing = match run_quinn_h3_client(address, payload, requests, handle) {
        Ok(timing) => Some(timing),
        Err(reason) => {
            print_quinn_not_available(payload, repetitions, reason);
            None
        }
    };
    if quinn_timing.is_some() {
        for _ in 1..repetitions {
            let timing = run_quinn_h3_client(address, payload, requests, handle)
                .unwrap_or_else(|reason| panic!("quinn H3 interop regressed mid-run: {reason}"));
            merge_timing(&mut quinn_timing, timing);
        }
    }
    print_result(
        ResultMetadata {
            case: "courierust_h3_client_to_courierust",
            layer: "client",
            protocol: Protocol::H3,
            client: "courierust-h3",
            server: "courierust-h3",
            payload,
            workers: 1,
            repetitions,
            server_threads: 4,
            pool_policy: "courierust_max_connections_per_host",
            pool_value: 1,
        },
        courierust_timing,
    );
    if let Some(quinn_timing) = quinn_timing {
        print_result(
            ResultMetadata {
                case: "quinn_h3_client_to_courierust",
                layer: "client",
                protocol: Protocol::H3,
                client: "quinn+h3",
                server: "courierust-h3",
                payload,
                workers: 1,
                repetitions,
                server_threads: 4,
                pool_policy: "quinn_single_connection",
                pool_value: 1,
            },
            quinn_timing,
        );
    }
}

fn main() {
    let requests = env_usize("BENCH_REQUESTS", 2_000);
    let large_body_requests = env_usize("BENCH_H2_LARGE_BODY_REQUESTS", requests.min(32));
    let parallel_requests = env_usize("BENCH_PARALLEL_REQUESTS", requests);
    let parallel_workers = env_usize("BENCH_COMPARE_WORKERS", 8);
    let repetitions = comparison_repetitions();
    // One shared tokio runtime drives the async reqwest client used for
    // the HTTP/2 rows. Note: the h2c large-body rows still show a large
    // fixed wait in the async client (h2 flow-control window pacing); it
    // is not a blocking-client artifact, so those rows are not suitable
    // for ratio claims (see `compare_h2_large_body`).
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("tokio runtime for async reqwest");
    let handle = runtime.handle().clone();
    println!("courierust comparison suite (loopback, shared-peer matrix)");
    println!(
        "META|suite=compare|requests_per_repetition={requests}|parallel_requests_per_repetition={parallel_requests}|parallel_workers={parallel_workers}|repetitions={repetitions}|max_samples={MAX_SAMPLES}"
    );

    raw_tcp_floor(requests);
    for protocol in [Protocol::H1, Protocol::H2c] {
        for payload in [ONE_KIB, SIXTY_FOUR_KIB] {
            let hyper = hyper_server(protocol, payload);
            let courierust = courierust_server(protocol, payload);
            compare_clients(protocol, hyper, payload, requests, 1, repetitions, &handle);
            compare_servers(
                protocol,
                courierust,
                hyper,
                payload,
                requests,
                repetitions,
                &handle,
            );
            if matches!(protocol, Protocol::H2c) && payload.bytes == SIXTY_FOUR_KIB.bytes {
                compare_h2_large_body(hyper, payload, large_body_requests, repetitions, &handle);
            }
            if payload.bytes == ONE_KIB.bytes {
                compare_clients(
                    protocol,
                    hyper,
                    payload,
                    parallel_requests,
                    parallel_workers,
                    repetitions,
                    &handle,
                );
            }
        }
    }

    // HTTP/3: Courierust H3 client vs quinn + h3 crate (warm reuse).
    for payload in [ONE_KIB, SIXTY_FOUR_KIB] {
        compare_h3_clients(payload, requests, repetitions, &handle);
    }

    drop(runtime);
    println!("total: complete");
}
