//! Courierust side of the TLS interop matrix (driven by `scripts/tls_interop.sh`).
//!
//! Connects to `COURIERUST_TLS_URL`, validates the cert against
//! `COURIERUST_TLS_ROOT`, reports the HTTP outcome. Body length is not
//! asserted — external servers' responses are not ours to pin. The TLS
//! version is forced by the peer (s_server / nginx) and proven by a
//! successful request. The mirror direction (a Courierust TLS server
//! validated by curl / openssl s_client) reuses the `network` server mode.

use courierust::courierust_client::{Client, ClientConfig, TlsSettings};
use courierust::courierust_http::method::Method;
use courierust::courierust_http::request::Request;

fn main() {
    let url = std::env::var("COURIERUST_TLS_URL").expect("COURIERUST_TLS_URL required");
    let root_path = std::env::var("COURIERUST_TLS_ROOT").expect("COURIERUST_TLS_ROOT required");
    let proto = std::env::var("COURIERUST_TLS_PROTO").unwrap_or_else(|_| "h1".to_string());
    let http2 = proto == "h2";

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
