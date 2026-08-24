//! Temporary repro: Courierust H3 client first, then quinn + h3 client,
//! against the SAME Courierust H3 server (mirrors `compare`).
//! Debugging only — delete after the interop issue is resolved.

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
                ..Default::default()
            }),
            ..Default::default()
        },
    )
    .expect("bind h3 server");
    let addr = server.local_addr().unwrap();
    let body = courierust::courierust_bytes::Bytes::from(vec![b'x'; 1024]);
    let handle = server
        .serve_background(move |_req: courierust::courierust_http::request::Request<
            courierust::courierust_body::Body,
        >| {
            courierust::courierust_http::response::Response::<
                courierust::courierust_body::Body,
            >::with_status(200.into())
            .with_body(courierust::courierust_body::Body::Bytes(body.clone()))
        })
        .expect("serve h3");
    std::mem::forget(handle);
    eprintln!("COURIERUST-H3-SERVER ready at {addr}");

    // --- Phase 1: Courierust client, 2000 requests (same as compare) ---
    {
        let mut roots = courierust::courierust_tls::RootStore::new();
        roots.add_der(include_bytes!("../certs/h3_ca.der").to_vec());
        let client = courierust::courierust_client::Client::with_config(
            courierust::courierust_client::ClientConfig {
                http3: true,
                max_connections_per_host: 1,
                read_timeout: Some(Duration::from_secs(10)),
                tls: Some(courierust::courierust_client::TlsSettings {
                    roots,
                    verify: true,
                    alpn: vec![b"h3".to_vec()],
                    now: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs() as i64,
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        let url = format!("https://{addr}/benchmark");
        for pass in 0..2 {
            for i in 0..2000usize {
                let response = client.get(&url).unwrap();
                assert_eq!(response.body.collect().unwrap().len(), 1024, "pass {pass} req {i}");
            }
            eprintln!("COURIERUST-CLIENT phase pass {pass}: 2000 requests OK");
        }
        drop(client);
    }

    // --- Phase 2: quinn + h3 client, 2000 requests (same as compare) ---
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
        Duration::from_secs(5)
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
                // Mirror `compare`: drive h3_conn from a spawned task.
                let handle = tokio::runtime::Handle::current();
                handle.spawn(async move {
                    let _ = h3_conn.wait_idle().await;
                });
                for i in 0..2000usize {
                    let req = http::Request::builder()
                        .uri(format!("https://{addr}/benchmark"))
                        .body(())
                        .expect("request");
                    let mut stream = match send_request.send_request(req).await {
                        Ok(s) => s,
                        Err(e) => return format!("send_request failed at {i}: {e:?}"),
                    };
                    if let Err(e) = stream.finish().await {
                        return format!("finish failed at {i}: {e:?}");
                    }
                    let resp = match stream.recv_response().await {
                        Ok(r) => r,
                        Err(e) => return format!("recv_response failed at {i}: {e:?}"),
                    };
                    let mut total = 0usize;
                    while let Some(chunk) = stream.recv_data().await.expect("recv data") {
                        total += chunk.remaining();
                    }
                    if resp.status().as_u16() != 200 || total != 1024 {
                        return format!("bad response at {i}: status={} total={total}", resp.status().as_u16());
                    }
                    if i % 500 == 0 {
                        eprintln!("QUINN request {i} OK");
                    }
                }
                eprintln!("QUINN phase: 2000 requests OK");
                "OK".to_string()
            }
            Ok(Err(e)) => format!("quinn handshake failed: {e:?}"),
            Err(_) => "quinn handshake timed out".to_string(),
        }
    });
    eprintln!("QUINN-H3 repro outcome: {outcome}");
}
