//! HTTPS (TLS 1.3) end-to-end example: a server with a self-signed
//! Ed25519 identity and a client that validates it, speaking `https://`.
//!
//! The identity files live in `tests/certs/` (DER):
//!   - `server_cert.der`: the self-signed leaf certificate
//!     (CN=localhost, SAN = DNS:localhost + IP:127.0.0.1)
//!   - `server_key.der` : the PKCS#8 Ed25519 private key
//!
//! The certificate is valid 2026-08-20 .. 2036-08-17. For a real
//! deployment, load your own certificate chain (leaf first) and PKCS#8 /
//! PKCS#1 private key instead of the test files.
//!
//! Run: `cargo run --example https`

use courierust::courierust_body::Body;
use courierust::courierust_client::{Client, ClientConfig, TlsSettings as ClientTls};
use courierust::courierust_http::request::Request;
use courierust::courierust_http::response::Response;
use courierust::courierust_server::{Server, ServerConfig, TlsSettings as ServerTls};

const CERT_DER: &[u8] = include_bytes!("../tests/certs/server_cert.der");
const KEY_DER: &[u8] = include_bytes!("../tests/certs/server_key.der");

fn main() -> courierust::Result<()> {
    // --- HTTPS server -------------------------------------------------
    let identity = courierust::courierust_tls::Identity {
        cert_chain: vec![CERT_DER.to_vec()],
        private_key: KEY_DER.to_vec(),
        is_rsa: false, // Ed25519
    };
    let server_cfg = ServerConfig {
        http2: true, // serve both h2 (ALPN) and HTTP/1.1 over TLS
        tls: Some(ServerTls {
            identity,
            alpn: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        }),
        ..Default::default()
    };
    let server = Server::bind_with_config("127.0.0.1:0", server_cfg)?;
    let addr = server.local_addr()?;
    let _handle = server.serve_background(|req: Request<Body>| -> Response<Body> {
        let mut resp = Response::with_status(200.into());
        resp.headers.insert(
            courierust::courierust_http::header::HeaderName::from_lowercase("content-type"),
            courierust::courierust_http::header::HeaderValue::from_static("text/plain"),
        );
        resp.body = Body::Bytes(req.body.collect().unwrap_or_default());
        resp
    })?;

    // --- HTTPS client -------------------------------------------------
    let mut roots = courierust::courierust_tls::RootStore::new();
    roots.add_der(CERT_DER.to_vec());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let client_cfg = ClientConfig {
        http2: true,
        tls: Some(ClientTls {
            roots,
            verify: true,
            alpn: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            now,
        }),
        ..Default::default()
    };
    let client = Client::with_config(client_cfg);

    let resp = client.get(&format!("https://{addr}/secure"))?;
    println!(
        "GET  https://{addr}/secure -> {} {}",
        resp.status.as_u16(),
        resp.body.collect()?.to_str()?
    );

    let resp = client.post(&format!("https://{addr}/echo"), "hello over TLS")?;
    println!(
        "POST https://{addr}/echo   -> {} {}",
        resp.status.as_u16(),
        resp.body.collect()?.to_str()?
    );

    Ok(())
}
