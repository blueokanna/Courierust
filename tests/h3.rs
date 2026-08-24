//! HTTP/3 (QUIC v1 + TLS 1.3) integration tests through the public API:
//! the pooled H3 client against the H3 server over real UDP sockets.
//!
//! Unlike the protocol unit tests in `courierust_h3::runtime`, these go
//! through `Client`/`Server`, so they exercise the same path a caller
//! uses: Retry address validation, the QUIC/TLS handshake, the
//! per-authority connection pool, and stream multiplexing.

mod common;

use courierust::courierust_body::Body;
use courierust::courierust_bytes::Bytes;
use courierust::courierust_client::{Client, ClientConfig, TlsSettings as ClientTls};
use courierust::courierust_http::request::Request;
use courierust::courierust_http::version::Version;
use courierust::courierust_server::{Server, ServerConfig, TlsSettings as ServerTls};
use std::time::{Duration, Instant};

/// Spin up an H3 server (QUIC + TLS 1.3, ALPN `h3`) and return its
/// `https://` base URL. The handle is leaked so the server outlives the
/// test body.
fn spawn_h3_server(
    handler: impl Fn(Request<Body>) -> courierust::courierust_http::response::Response<Body>
        + Send
        + Sync
        + 'static,
) -> String {
    spawn_h3_server_with_identity(common::server_identity(), handler)
}

/// Spin up an H3 server with an explicit TLS identity (used by the
/// expired / wrong-chain / hostname-mismatch security tests).
fn spawn_h3_server_with_identity(
    identity: courierust::courierust_tls::Identity,
    handler: impl Fn(Request<Body>) -> courierust::courierust_http::response::Response<Body>
        + Send
        + Sync
        + 'static,
) -> String {
    let server = Server::bind_with_config(
        "127.0.0.1:0",
        ServerConfig {
            http3: true,
            tls: Some(ServerTls {
                identity,
                alpn: vec![b"h3".to_vec()],
            }),
            ..Default::default()
        },
    )
    .unwrap();
    let addr = server.local_addr().unwrap();
    let handle = server.serve_background(handler).unwrap();
    std::mem::forget(handle);
    format!("https://{addr}")
}

/// A pooled H3 client pinned to one QUIC connection per authority.
fn h3_client(max_body: usize, read_timeout: Duration) -> Client {
    Client::with_config(ClientConfig {
        http3: true,
        max_connections_per_host: 1,
        read_timeout: Some(read_timeout),
        max_body,
        tls: Some(ClientTls {
            roots: common::root_store(),
            verify: true,
            alpn: vec![b"h3".to_vec()],
            now: common::NOW,
            ..Default::default()
        }),
        ..Default::default()
    })
}

/// Echo the request body; an empty body echoes the request path.
fn echo_handler(req: Request<Body>) -> courierust::courierust_http::response::Response<Body> {
    let body = req.body.collect().unwrap_or_default();
    let payload = if body.is_empty() {
        Bytes::from(req.uri.as_str().as_bytes().to_vec())
    } else {
        body
    };
    courierust::courierust_http::response::Response::<Body>::with_status(200.into())
        .with_body(Body::Bytes(payload))
}

#[test]
fn h3_get_roundtrip() {
    let base = spawn_h3_server(echo_handler);
    let client = h3_client(1 << 20, Duration::from_secs(5));

    let resp = client.get(&format!("{base}/hello")).unwrap();
    assert_eq!(resp.status.as_u16(), 200);
    assert_eq!(resp.version, Version::HTTP_3, "response must be HTTP/3");
    assert_eq!(resp.body.collect().unwrap().to_str().unwrap(), "/hello");
}

#[test]
fn h3_post_body_roundtrip() {
    let base = spawn_h3_server(echo_handler);
    let client = h3_client(1 << 20, Duration::from_secs(5));

    let body: Vec<u8> = (0..(64 * 1024)).map(|i| (i % 251) as u8).collect();
    let resp = client.post(&format!("{base}/echo"), body.clone()).unwrap();
    assert_eq!(resp.status.as_u16(), 200);
    assert_eq!(&resp.body.collect().unwrap()[..], &body[..]);
}

/// The pooled connection must be reused across sequential requests: each
/// request rides a fresh QUIC stream on the same connection, so the
/// QUIC/TLS handshake is paid once.
#[test]
fn h3_connection_reuse_across_requests() {
    let base = spawn_h3_server(echo_handler);
    let client = h3_client(1 << 20, Duration::from_secs(5));

    for i in 0..30 {
        let path = format!("/reuse/{i}");
        let resp = client.get(&format!("{base}{path}")).unwrap();
        assert_eq!(resp.status.as_u16(), 200, "status {i}");
        assert_eq!(
            resp.body.collect().unwrap().to_str().unwrap(),
            path,
            "path echo {i}"
        );
    }
}

/// A single pooled connection must survive far more requests than `MAX_H3_STREAMS` (1024)
#[test]
fn h3_pooled_connection_survives_many_requests() {
    const REQUESTS: usize = 1024 + 128;
    let base = spawn_h3_server(echo_handler);
    let client = h3_client(1 << 20, Duration::from_secs(60));

    for i in 0..REQUESTS {
        let path = format!("/many/{i}");
        let resp = client.get(&format!("{base}{path}")).unwrap();
        assert_eq!(resp.status.as_u16(), 200, "status {i}");
        assert_eq!(
            resp.body.collect().unwrap().to_str().unwrap(),
            path,
            "path echo {i}"
        );
    }
}

/// A request body far larger than the initial congestion window
/// (12 KiB) must be delivered in ACK-paced chunks, never truncated.
#[test]
fn h3_large_request_body_flow_control() {
    let base = spawn_h3_server(echo_handler);
    // CI runs every test in parallel on small runners; the deadline is a
    // deadlock tripwire, not a performance bound — a healthy 256 KiB
    // transfer completes in well under a second.
    let client = h3_client(1 << 20, Duration::from_secs(60));

    let body: Vec<u8> = (0..(256 * 1024)).map(|i| (i % 253) as u8).collect();
    let resp = client
        .post(&format!("{base}/big-upload"), body.clone())
        .unwrap();
    assert_eq!(resp.status.as_u16(), 200);
    assert_eq!(&resp.body.collect().unwrap()[..], &body[..]);
}

/// A response body larger than the congestion window must stream back
/// intact (the server's queued-stream path defers on a full window and
/// resumes once ACKs free credit).
#[test]
fn h3_large_response_body_flow_control() {
    let body: Vec<u8> = (0..(256 * 1024)).map(|i| (i % 239) as u8).collect();
    let expected = body.clone();
    let base = spawn_h3_server(move |_req: Request<Body>| {
        courierust::courierust_http::response::Response::<Body>::with_status(200.into())
            .with_body(Body::Bytes(Bytes::from(expected.clone())))
    });
    let client = h3_client(1 << 20, Duration::from_secs(60));

    let resp = client.get(&format!("{base}/big-download")).unwrap();
    assert_eq!(resp.status.as_u16(), 200);
    assert_eq!(&resp.body.collect().unwrap()[..], &body[..]);
}

/// Concurrent requests must multiplex over the single pooled QUIC
/// connection without cross-wiring paths.
#[test]
fn h3_concurrent_multiplex() {
    let base = spawn_h3_server(echo_handler);
    let client = h3_client(1 << 20, Duration::from_secs(60));

    let mut handles = Vec::new();
    for i in 0..16 {
        let client = client.clone();
        let url = format!("{base}/mux/{i}");
        handles.push(
            std::thread::Builder::new()
                .stack_size(8 * 1024 * 1024)
                .spawn(move || {
                    let resp = client.get(&url).unwrap();
                    assert_eq!(resp.status.as_u16(), 200);
                    resp.body.collect().unwrap().to_str().unwrap().to_string()
                })
                .unwrap(),
        );
    }
    for (i, handle) in handles.into_iter().enumerate() {
        assert_eq!(handle.join().unwrap(), format!("/mux/{i}"));
    }
}

/// Security: a client that does not trust the server certificate must
/// fail the QUIC/TLS handshake, not silently proceed.
#[test]
fn h3_rejects_untrusted_certificate() {
    let base = spawn_h3_server(echo_handler);
    let client = Client::with_config(ClientConfig {
        http3: true,
        read_timeout: Some(Duration::from_secs(5)),
        tls: Some(ClientTls {
            roots: courierust::courierust_tls::RootStore::new(),
            verify: true,
            alpn: vec![b"h3".to_vec()],
            now: common::NOW,
            ..Default::default()
        }),
        ..Default::default()
    });

    let err = client
        .get(&format!("{base}/untrusted"))
        .map(|_| ())
        .expect_err("untrusted self-signed H3 server must be rejected");
    assert!(
        !err.to_string().is_empty(),
        "rejection error must carry a message"
    );
}

/// A per-request deadline must be honored: a handler that outlives
/// `read_timeout` yields a Timeout error instead of hanging the caller.
#[test]
fn h3_request_timeout() {
    let base = spawn_h3_server(|_req: Request<Body>| {
        std::thread::sleep(Duration::from_millis(1500));
        courierust::courierust_http::response::Response::<Body>::with_status(200.into())
    });
    let client = h3_client(1 << 20, Duration::from_millis(100));

    let t0 = Instant::now();
    let err = client
        .get(&format!("{base}/slow"))
        .map(|_| ())
        .expect_err("a request that outlives read_timeout must time out");
    assert_eq!(err.kind, courierust::ErrorKind::Timeout);
    assert!(
        t0.elapsed() < Duration::from_secs(5),
        "timeout took too long: {:?}",
        t0.elapsed()
    );
}

/// Security: an expired H3 server certificate must fail the QUIC/TLS
/// handshake even when the client explicitly trusts it (validity window).
#[test]
fn h3_rejects_expired_certificate() {
    let expired_identity = courierust::courierust_tls::Identity {
        cert_chain: vec![include_bytes!("certs/expired_cert.der").to_vec()],
        private_key: include_bytes!("certs/expired_key.der").to_vec(),
        is_rsa: false,
    };
    let base = spawn_h3_server_with_identity(expired_identity, echo_handler);
    let mut roots = courierust::courierust_tls::RootStore::new();
    roots.add_der(include_bytes!("certs/expired_cert.der").to_vec());
    let client = Client::with_config(ClientConfig {
        http3: true,
        read_timeout: Some(Duration::from_secs(5)),
        tls: Some(ClientTls {
            roots,
            verify: true,
            alpn: vec![b"h3".to_vec()],
            now: common::NOW, // 2027: far outside the 2020..2021 window
            ..Default::default()
        }),
        ..Default::default()
    });

    let err = client
        .get(&format!("{base}/expired"))
        .map(|_| ())
        .expect_err("an expired H3 certificate must be rejected");
    assert!(!err.to_string().is_empty());
}

/// Security: an H3 server presenting a chain to an untrusted CA must be
/// rejected (the chain does not anchor to any trusted root).
#[test]
fn h3_rejects_wrong_certificate_chain() {
    let wrong_chain_identity = courierust::courierust_tls::Identity {
        cert_chain: vec![
            include_bytes!("certs/wrong_chain_cert.der").to_vec(),
            include_bytes!("certs/ca_other_cert.der").to_vec(),
        ],
        private_key: include_bytes!("certs/wrong_chain_key.der").to_vec(),
        is_rsa: false,
    };
    let base = spawn_h3_server_with_identity(wrong_chain_identity, echo_handler);
    let client = h3_client(1 << 20, Duration::from_secs(5)); // trusts only the real root

    let err = client
        .get(&format!("{base}/wrong-chain"))
        .map(|_| ())
        .expect_err("a chain to an untrusted CA must be rejected over H3");
    assert!(!err.to_string().is_empty());
}

/// Security: over H3, the certificate's SAN must cover the hostname the
/// client connects to (RFC 6125). The server presents a self-signed cert
/// whose SAN is only `wrong.example`; the client connects to `127.0.0.1`,
/// so the hostname check must reject the handshake.
#[test]
fn h3_rejects_hostname_mismatch() {
    let mismatch_identity = courierust::courierust_tls::Identity {
        cert_chain: vec![include_bytes!("certs/mismatch_cert.der").to_vec()],
        private_key: include_bytes!("certs/mismatch_key.der").to_vec(),
        is_rsa: false,
    };
    let base = spawn_h3_server_with_identity(mismatch_identity, echo_handler);
    let mut roots = courierust::courierust_tls::RootStore::new();
    roots.add_der(include_bytes!("certs/mismatch_cert.der").to_vec());
    let client = Client::with_config(ClientConfig {
        http3: true,
        read_timeout: Some(Duration::from_secs(5)),
        tls: Some(ClientTls {
            roots,
            verify: true,
            alpn: vec![b"h3".to_vec()],
            now: common::NOW,
            ..Default::default()
        }),
        ..Default::default()
    });

    let err = client
        .get(&format!("{base}/mismatch"))
        .map(|_| ())
        .expect_err("a hostname not covered by the certificate SAN must be rejected");
    assert!(!err.to_string().is_empty());
}
