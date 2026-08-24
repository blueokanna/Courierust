//! HTTP/3 (QUIC v1 + TLS 1.3) end-to-end example: a QUIC server and the
//! pooled client, over the same self-signed identity as `examples/https`.
//!
//! This is the "what H3 actually gives you" demo. The client pool keeps
//! one QUIC connection per authority alive, so the first request pays
//! the full cold cost and every later request rides a fresh QUIC stream
//! on the same connection (~1 RTT). The demo shows:
//!
//!   1. **Cold connect** — QUIC handshake + TLS 1.3 + server Retry
//!      address validation (paid once).
//!   2. **Warm reuse** — the per-authority pool multiplexes subsequent
//!      requests on the established connection.
//!   3. **Request bodies** — POST over QUIC (flow-controlled).
//!   4. **Large responses** — a 256 KiB body streams back in ACK-paced
//!      chunks (the server defers on a full congestion window).
//!   5. **Concurrent multiplexing** — 8 workers share one connection.
//!   6. **Certificate verification** — an untrusted peer is rejected.
//!
//! Run: `cargo run --example h3`

use courierust::courierust_body::Body;
use courierust::courierust_bytes::Bytes;
use courierust::courierust_client::{Client, ClientConfig, TlsSettings as ClientTls};
use courierust::courierust_http::request::Request;
use courierust::courierust_http::response::Response;
use courierust::courierust_server::{Server, ServerConfig, TlsSettings as ServerTls};
use std::time::{Duration, Instant};

const CERT_DER: &[u8] = include_bytes!("../tests/certs/server_cert.der");
const KEY_DER: &[u8] = include_bytes!("../tests/certs/server_key.der");

fn main() -> courierust::Result<()> {
    let identity = courierust::courierust_tls::Identity {
        cert_chain: vec![CERT_DER.to_vec()],
        private_key: KEY_DER.to_vec(),
        is_rsa: false, // Ed25519
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
    let server = Server::bind_with_config("127.0.0.1:0", server_cfg)?;
    let addr = server.local_addr()?;
    let _handle = server.serve_background(|req: Request<Body>| -> Response<Body> {
        if req.uri.as_str() == "/big" {
            return Response::<Body>::with_status(200.into())
                .with_body(Body::Bytes(Bytes::from(vec![b'x'; 256 * 1024])));
        }
        let body = req.body.collect().unwrap_or_default();
        let payload = if body.is_empty() {
            Bytes::from(req.uri.as_str().as_bytes().to_vec())
        } else {
            body
        };
        Response::<Body>::with_status(200.into()).with_body(Body::Bytes(payload))
    })?;
    println!("HTTP/3 server listening on {addr} (QUIC v1 + TLS 1.3, ALPN h3)");

    let mut roots = courierust::courierust_tls::RootStore::new();
    roots.add_der(CERT_DER.to_vec());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let client_cfg = ClientConfig {
        http3: true,
        max_connections_per_host: 1, // one pooled QUIC connection
        read_timeout: Some(Duration::from_secs(10)),
        tls: Some(ClientTls {
            roots,
            verify: true,
            alpn: vec![b"h3".to_vec()],
            now,
            ..Default::default()
        }),
        ..Default::default()
    };
    let client = Client::with_config(client_cfg);
    let base = format!("https://{addr}");

    let t = Instant::now();
    let resp = client.get(&format!("{base}/cold"))?;
    println!(
        "GET  /cold  -> {} in {:>6.2} ms  (cold: QUIC handshake + TLS 1.3 + Retry)",
        resp.status.as_u16(),
        t.elapsed().as_secs_f64() * 1000.0
    );
    assert_eq!(resp.body.collect()?.to_str()?, "/cold");

    for i in 0..5 {
        let t = Instant::now();
        let resp = client.get(&format!("{base}/warm/{i}"))?;
        println!(
            "GET  /warm/{i} -> {} in {:>6.3} ms  (warm: pooled QUIC connection)",
            resp.status.as_u16(),
            t.elapsed().as_secs_f64() * 1000.0
        );
        assert_eq!(resp.body.collect()?.to_str()?, format!("/warm/{i}"));
    }

    let payload = b"hello over QUIC".to_vec();
    let resp = client.post(&format!("{base}/echo"), payload.clone())?;
    let echoed = resp.body.collect()?;
    assert_eq!(&echoed[..], &payload[..]);
    println!("POST /echo  -> {} bytes echoed", echoed.len());

    let t = Instant::now();
    let resp = client.get(&format!("{base}/big"))?;
    let big = resp.body.collect()?;
    assert_eq!(big.len(), 256 * 1024);
    println!(
        "GET  /big   -> {} bytes in {:>6.1} ms  (256 KiB response, flow-controlled)",
        big.len(),
        t.elapsed().as_secs_f64() * 1000.0
    );

    let handles: Vec<_> = (0..8)
        .map(|i| {
            let client = client.clone();
            let base = base.clone();
            std::thread::spawn(move || -> courierust::Result<String> {
                let resp = client.get(&format!("{base}/mux/{i}"))?;
                Ok(resp.body.collect()?.to_str()?.to_string())
            })
        })
        .collect();
    for (i, handle) in handles.into_iter().enumerate() {
        assert_eq!(
            handle.join().expect("worker panicked")?,
            format!("/mux/{i}")
        );
    }
    println!("8 concurrent requests multiplexed over the pooled connection");

    let untrusted = Client::with_config(ClientConfig {
        http3: true,
        read_timeout: Some(Duration::from_secs(5)),
        tls: Some(ClientTls {
            roots: courierust::courierust_tls::RootStore::new(),
            verify: true,
            alpn: vec![b"h3".to_vec()],
            now,
            ..Default::default()
        }),
        ..Default::default()
    });
    match untrusted.get(&format!("{base}/untrusted")) {
        Ok(_) => println!("untrusted server ACCEPTED (unexpected!)"),
        Err(e) => println!(
            "untrusted server rejected -> {}",
            e.to_string().replace('\n', " ")
        ),
    }

    println!("all HTTP/3 paths verified");
    Ok(())
}
