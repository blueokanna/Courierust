//! Minimal quinn -> Courierust H3 interop probe (debugging only).
//!
//! Runs the real Courierust HTTP/3 server, then a stock quinn + h3 client
//! (the same combination the `compare` bench uses) and reports exactly
//! where the independent handshake fails. Run with
//! `COURIERUST_H3_DEBUG=1` to see Courierust's transport-level tracing.

use std::sync::Arc;
use std::time::Duration;

use bytes::Buf;

fn main() {
    let identity = courierust::courierust_tls::Identity {
        cert_chain: vec![include_bytes!("../certs/h3_server.der").to_vec()],
        private_key: include_bytes!("../certs/h3_server_key.der").to_vec(),
        is_rsa: false,
    };
    let server = courierust::courierust_server::Server::bind_with_config(
        "127.0.0.1:0",
        courierust::courierust_server::ServerConfig {
            http3: true,
            threads: 4,
            tls: Some(courierust::courierust_server::TlsSettings {
                identity,
                alpn: vec![b"h3".to_vec()],
            }),
            ..Default::default()
        },
    )
    .expect("bind h3 server");
    let addr = server.local_addr().unwrap();
    let handle = server
        .serve_background(|_req: courierust::courierust_http::request::Request<
            courierust::courierust_body::Body,
        >| {
            courierust::courierust_http::response::Response::<
                courierust::courierust_body::Body,
            >::with_status(200.into())
            .with_body(courierust::courierust_body::Body::from(
                courierust::courierust_bytes::Bytes::from_static(b"ok"),
            ))
        })
        .expect("serve h3");
    std::mem::forget(handle);
    eprintln!("COURIERUST-H3-SERVER ready at {addr}");

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let _ = rustls::crypto::CryptoProvider::install_default(
        rustls::crypto::aws_lc_rs::default_provider(),
    );
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(
            include_bytes!("../certs/h3_ca.der").to_vec(),
        ))
        .expect("CA parses");
    let mut crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    crypto.alpn_protocols = vec![b"h3".to_vec()];
    crypto.enable_early_data = false;
    let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(crypto).expect("quic config");

    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        Duration::from_secs(30)
            .try_into()
            .expect("idle timeout"),
    ));
    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_crypto));
    client_config.transport_config(Arc::new(transport));

    let outcome = runtime.block_on(async move {
        let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(client_config);
        let connecting = endpoint.connect(addr, "localhost").expect("connect");
        match tokio::time::timeout(Duration::from_secs(6), connecting).await {
            Ok(Ok(connection)) => {
                let (mut h3_conn, mut send_request) = h3::client::builder()
                    .build::<_, _, bytes::Bytes>(h3_quinn::Connection::new(connection))
                    .await
                    .expect("h3 connect");
                // Send enough requests to cross quinn's automatic key-update
                // threshold (10..1000 packets per phase), exercising the
                // RFC 9001 §6 bidirectional key update against Courierust.
                for i in 0..2000usize {
                    let req = http::Request::builder()
                        .uri(format!("https://{addr}/probe/{i}"))
                        .body(())
                        .expect("request");
                    let mut stream = send_request.send_request(req).await.expect("send");
                    stream.finish().await.expect("finish");
                    let resp = stream.recv_response().await.expect("response");
                    let mut total = 0usize;
                    while let Some(chunk) = stream.recv_data().await.expect("recv data") {
                        total += chunk.remaining();
                    }
                    if resp.status().as_u16() != 200 {
                        eprintln!("QUINN-H3 request {i}: status={}", resp.status().as_u16());
                        return format!("bad status at request {i}");
                    }
                    if total != 2 {
                        eprintln!("QUINN-H3 request {i}: body_len={total}");
                        return format!("bad body at request {i}");
                    }
                }
                eprintln!("QUINN-H3 probe: 2000 requests OK");
                let _ = h3_conn.wait_idle().await;
                "OK".to_string()
            }
            Ok(Err(e)) => format!("quinn handshake failed: {e:?}"),
            Err(_) => "quinn handshake timed out".to_string(),
        }
    });
    eprintln!("QUINN-H3 probe outcome: {outcome}");
}
