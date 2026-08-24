//! TLS version window: `COURIERUST_TLS_MIN_VERSION` /
//! `COURIERUST_TLS_MAX_VERSION` (e.g. `TLSv1.2`) pin the ClientHello. A
//! TLS 1.2-only peer (OpenSSL `s_server -tls1_2`, nginx with
//! `ssl_protocols TLSv1.2`) MUST NOT see a `supported_versions` extension
//! advertising TLS 1.3 — OpenSSL rejects such a ClientHello outright.
//! The mirror direction (a Courierust TLS server validated by curl /
//! openssl s_client) reuses the `network` server mode.

use courierust::courierust_client::{Client, ClientConfig, TlsSettings};
use courierust::courierust_http::method::Method;
use courierust::courierust_http::request::Request;
use courierust::courierust_tls::TlsVersion;

fn version_from_env(name: &str, fallback: TlsVersion) -> TlsVersion {
    std::env::var(name)
        .ok()
        .and_then(|v| match v.as_str() {
            "TLSv1.2" | "TLSv1_2" | "1.2" => Some(TlsVersion::Tls12),
            "TLSv1.3" | "TLSv1_3" | "1.3" => Some(TlsVersion::Tls13),
            _ => None,
        })
        .unwrap_or(fallback)
}

fn main() {
    let url = std::env::var("COURIERUST_TLS_URL").expect("COURIERUST_TLS_URL required");
    let root_path = std::env::var("COURIERUST_TLS_ROOT").expect("COURIERUST_TLS_ROOT required");
    let proto = std::env::var("COURIERUST_TLS_PROTO").unwrap_or_else(|_| "h1".to_string());
    let http2 = proto == "h2";
    let min_version = version_from_env("COURIERUST_TLS_MIN_VERSION", TlsVersion::Tls12);
    let max_version = version_from_env("COURIERUST_TLS_MAX_VERSION", TlsVersion::Tls13);

    let mut roots = courierust::courierust_tls::RootStore::new();
    roots.add_der(
        std::fs::read(&root_path)
            .unwrap_or_else(|e| panic!("read root certificate {root_path}: {e}")),
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let client = Client::with_config(ClientConfig {
        http2,
        max_connections_per_host: 1,
        tls: Some(TlsSettings {
            roots,
            verify: true,
            alpn: if http2 {
                vec![b"h2".to_vec(), b"http/1.1".to_vec()]
            } else {
                vec![b"http/1.1".to_vec()]
            },
            now,
            min_version,
            max_version,
        }),
        ..Default::default()
    });

    let req = Request::new(Method::GET, "/");
    let resp = match client.execute(&url, req) {
        Ok(r) => r,
        Err(e) => {
            println!(
                "TLSINTEROP|role=client|peer=external|protocol={proto}|status=failed|error={}",
                e.to_string().replace('|', "/")
            );
            std::process::exit(1);
        }
    };
    let code = resp.status.as_u16();
    let body_len = resp.body.collect().map(|b| b.len()).unwrap_or(0);
    if code != 200 {
        println!("TLSINTEROP|role=client|peer=external|protocol={proto}|status=failed|http={code}");
        std::process::exit(1);
    }
    println!(
        "TLSINTEROP|role=client|peer=external|protocol={proto}|status=ok|http=200|body_bytes={body_len}"
    );
}
