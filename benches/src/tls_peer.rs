//! Independent TLS peer (rustls + hyper) for the TLS interop matrix.
//!
//! `scripts/tls_interop.sh` already exercises the Courierust TLS layer
//! against OpenSSL, curl and nginx. This bench adds the other mainstream
//! Rust stack as an independent peer, both directions:
//!
//!   `rustls_client`       rustls client → Courierust TLS server
//!   `hyper_https_server`  hyper + rustls server ← Courierust TLS client
//!
//! Mode is selected by `TLS_PEER_ROLE`; the other settings are the same
//! environment variables the interop script passes to `tls_interop`.

use std::sync::Arc;

fn main() {
    match std::env::var("TLS_PEER_ROLE").as_deref() {
        Ok("rustls_client") => rustls_client().expect("rustls client failed"),
        Ok("hyper_https_server") => hyper_https_server().expect("hyper https server failed"),
        Ok(other) => {
            eprintln!(
                "TLS_PEER_ROLE must be rustls_client or hyper_https_server, got {other:?}"
            );
            std::process::exit(2);
        }
        Err(_) => {
            eprintln!("TLS_PEER_ROLE is required");
            std::process::exit(2);
        }
    }
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
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
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
        let (mut sender, conn) = hyper::client::conn::http1::handshake(
            hyper_util::rt::TokioIo::new(tls_stream),
        )
        .await
        .expect("http1 handshake");
        tokio::spawn(conn);
        let path = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
        let req = hyper::Request::builder()
            .uri(path)
            .body(http_body_util::Empty::<bytes::Bytes>::new())
            .expect("build request");
        let resp = sender.send_request(req).await.expect("send request");
        let status = resp.status().as_u16();
        let body = http_body_util::BodyExt::collect(resp.into_body())
            .await
            .expect("collect body");
        println!(
            "TLSINTEROP|role=peer|peer=rustls_hyper_client|tls=TLSv1.3|protocol=h1|status={status}|body_bytes={}",
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
    let key_der = rustls::pki_types::PrivateKeyDer::try_from(
        rustls::pki_types::PrivatePkcs8KeyDer::from(std::fs::read(&key_path)?),
    )
    .expect("parse private key");
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .expect("server certificate config");
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
