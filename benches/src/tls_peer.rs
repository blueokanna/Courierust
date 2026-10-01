//! Independent TLS peer (rustls + hyper) for the TLS interop matrix.
//!
//! `scripts/tls_interop.sh` runs the Courierust TLS layer against OpenSSL,
//! curl and nginx; sections D and E of that script drive this binary, which
//! adds the mainstream *Rust* stack as a fourth independent peer, both
//! directions:
//!
//!   `rustls_client`       rustls + hyper client -> Courierust TLS server
//!                         env: `TLS_PEER_URL`, `TLS_PEER_ROOT`
//!   `hyper_https_server`  hyper + rustls server <- Courierust TLS client
//!                         env: `TLS_PEER_BIND`, `TLS_PEER_CERT`, `TLS_PEER_KEY`
//!
//! Both roles pin ALPN to `http/1.1` (the h2-over-TLS direction belongs to
//! nginx) and print a `TLSINTEROP|` evidence line that the workflow summary
//! parses.

use std::sync::Arc;

fn main() {
    // rustls 0.23 needs a process-level provider when more than one is
    // compiled in (this bench workspace also links quinn/reqwest). Install
    // the same one `compare` uses instead of letting the choice be implicit.
    let _ = rustls::crypto::CryptoProvider::install_default(
        rustls::crypto::aws_lc_rs::default_provider(),
    );
    match std::env::var("TLS_PEER_ROLE").as_deref() {
        Ok("rustls_client") => rustls_client().expect("rustls client failed"),
        Ok("hyper_https_server") => hyper_https_server().expect("hyper https server failed"),
        Ok(other) => {
            eprintln!("TLS_PEER_ROLE must be rustls_client or hyper_https_server, got {other:?}");
            std::process::exit(2);
        }
        Err(_) => {
            eprintln!("TLS_PEER_ROLE is required");
            std::process::exit(2);
        }
    }
}

/// Wire-level name for the negotiated TLS version, matching the labels the
/// interop script and the workflow summary use (`TLSv1.3`, `TLSv1.2`).
fn version_label(version: Option<rustls::ProtocolVersion>) -> &'static str {
    match version {
        Some(rustls::ProtocolVersion::TLSv1_3) => "TLSv1.3",
        Some(rustls::ProtocolVersion::TLSv1_2) => "TLSv1.2",
        _ => "unknown",
    }
}

/// Negotiated ALPN protocol as text, or `none` when the peer selected none.
fn alpn_label(protocol: Option<&[u8]>) -> String {
    protocol
        .map(|p| String::from_utf8_lossy(p).into_owned())
        .unwrap_or_else(|| "none".to_string())
}

/// rustls client → Courierust TLS server. The certificate must chain to
/// `TLS_PEER_ROOT`; a 200 proves Courierust's server TLS works against
/// rustls (an independent implementation).
fn rustls_client() -> Result<(), Box<dyn std::error::Error>> {
    let url = std::env::var("TLS_PEER_URL").expect("TLS_PEER_URL required");
    let root_path = std::env::var("TLS_PEER_ROOT").expect("TLS_PEER_ROOT required");
    let root = std::fs::read(&root_path).expect("read root");
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(root))
        .expect("root certificate parses");
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    // The Courierust server on this path advertises `http/1.1`, so offer
    // exactly that: a client that offers no ALPN would connect but would
    // prove nothing about protocol selection.
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let tls = tokio_rustls::TlsConnector::from(Arc::new(config));

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let uri: http::Uri = url.parse().expect("parse URL");
        let host = uri.host().expect("URL host").to_string();
        let port = uri.port_u16().unwrap_or(443);
        let stream = tokio::net::TcpStream::connect((host.as_str(), port))
            .await
            .expect("connect");
        let server_name = rustls::pki_types::ServerName::try_from(host.clone())
            .expect("valid server name")
            .to_owned();
        let tls_stream = tls
            .connect(server_name, stream)
            .await
            .expect("rustls handshake");
        // Read the negotiated version/ALPN off the live connection before
        // the stream is handed to hyper — the evidence line must carry what
        // was actually negotiated, not what was requested.
        let negotiated = version_label(tls_stream.get_ref().1.protocol_version());
        let negotiated_alpn = alpn_label(tls_stream.get_ref().1.alpn_protocol());
        let (mut sender, conn) = hyper::client::conn::http1::handshake(
            hyper_util::rt::TokioIo::new(tls_stream),
        )
        .await
        .expect("http1 handshake");
        tokio::spawn(conn);
        let path = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
        // RFC 9112 §3.2: an HTTP/1.1 request without `Host` must be answered
        // with 400. A raw `hyper::client::conn::http1` connection does not
        // add the field on its own, so the peer sends the authority it
        // dialled — the Courierust server correctly rejects it otherwise.
        let authority = uri
            .authority()
            .map(|a| a.as_str().to_string())
            .unwrap_or_else(|| host.clone());
        let req = hyper::Request::builder()
            .uri(path)
            .header(hyper::header::HOST, authority)
            .body(http_body_util::Empty::<bytes::Bytes>::new())
            .expect("build request");
        let resp = sender.send_request(req).await.expect("send request");
        let status = resp.status().as_u16();
        let body = http_body_util::BodyExt::collect(resp.into_body())
            .await
            .expect("collect body");
        println!(
            "TLSINTEROP|role=peer|peer=rustls_hyper_client|tls={negotiated}|protocol=h1|negotiated_alpn={negotiated_alpn}|status={status}|body_bytes={}",
            body.to_bytes().len()
        );
        if status != 200 {
            std::process::exit(1);
        }
    });
    Ok(())
}

/// hyper + rustls HTTPS server, exercised by the Courierust TLS client.
/// Serves HTTP/1.1 over TLS; ALPN is `http/1.1` only, so a Courierust
/// client must negotiate h1 (the h2-over-TLS path is covered by nginx).
fn hyper_https_server() -> Result<(), Box<dyn std::error::Error>> {
    use hyper::service::service_fn;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::server::conn::auto::Builder as AutoBuilder;
    use std::convert::Infallible;

    let bind = std::env::var("TLS_PEER_BIND").expect("TLS_PEER_BIND required");
    let cert_path = std::env::var("TLS_PEER_CERT").expect("TLS_PEER_CERT required");
    let key_path = std::env::var("TLS_PEER_KEY").expect("TLS_PEER_KEY required");
    let cert_der = rustls::pki_types::CertificateDer::from(std::fs::read(&cert_path)?);
    let key_der = rustls::pki_types::PrivateKeyDer::from(
        rustls::pki_types::PrivatePkcs8KeyDer::from(std::fs::read(&key_path)?),
    );
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .expect("server certificate config");
    // h1 only, matching the doc comment on this role: the Courierust client
    // must negotiate `http/1.1` here, and no other protocol is offered.
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let listener = tokio::net::TcpListener::bind(&bind).await.expect("bind");
        println!("TLSINTEROP|role=peer|peer=rustls_hyper_server|listen={bind}|status=ok");
        loop {
            let (stream, _) = listener.accept().await.expect("accept");
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(stream).await else {
                    return;
                };
                // Same rule as the client role: report the negotiated
                // version/ALPN, so the script's row cannot claim a version
                // the handshake did not actually pick.
                println!(
                    "TLSINTEROP|role=peer|peer=rustls_hyper_server|tls={}|protocol=h1|negotiated_alpn={}|status=handshake_ok",
                    version_label(tls.get_ref().1.protocol_version()),
                    alpn_label(tls.get_ref().1.alpn_protocol()),
                );
                let service =
                    service_fn(|_req: hyper::Request<hyper::body::Incoming>| async move {
                        Ok::<_, Infallible>(hyper::Response::new(
                            http_body_util::Full::new(bytes::Bytes::from_static(b"ok")),
                        ))
                    });
                let _ = AutoBuilder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(tls), service)
                    .await;
            });
        }
    })
}
