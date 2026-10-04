//! One-shot wire probe: connect to `url` with the Chrome-shaped
//! ClientHello profile and print the outcome.
//!
//! Used to isolate handshake interop failures: point it at
//! `openssl s_server -trace` locally to see exactly how a strict parser
//! reads our profiled hello, or at a remote endpoint to check whether a
//! rejection is wire-level or policy-level.
//!
//! ```text
//! cargo run --example profile_probe -- https://127.0.0.1:14433/ --insecure
//! cargo run --example profile_probe -- https://api.bilibili.com/x/web-interface/nav
//! ```

use courierust::courierust_client::{Client, ClientConfig, TlsSettings};
use courierust::courierust_fingerprint::{chrome_tls_profile, TlsProfile};
use courierust::courierust_http::method::Method;
use courierust::courierust_http::request::Request;
use courierust::courierust_tls::{RootStore, TlsVersion};
use std::time::Duration;

/// The parameter set of `openssl s_client` (the shape OpenSSL-based
/// clients — curl, wget, countless tools — present, and one known to be
/// accepted by otherwise picky endpoints).
fn openssl_style_profile() -> TlsProfile {
    TlsProfile {
        protocol: 't',
        tls_version: 0x0303,
        supported_versions: vec![0x0304, 0x0303],
        has_sni: true,
        ciphers: vec![
            0x1302, 0x1303, 0x1301, 0xc02c, 0xc030, 0x009f, 0xcca9, 0xcca8, 0xccaa, 0xc02b, 0xc02f,
            0x009e, 0xc024, 0xc028, 0x006b, 0xc023, 0xc027, 0x0067, 0xc00a, 0xc014, 0x0039, 0xc009,
            0xc013, 0x0033, 0x009d, 0x009c, 0x003d, 0x003c, 0x0035, 0x002f,
        ],
        extensions: vec![
            0x0000, 0xff01, 0x000b, 0x000a, 0x0023, 0x0016, 0x0017, 0x000d, 0x002b, 0x002d, 0x0033,
        ],
        signature_algorithms: vec![
            0x0905, 0x0906, 0x0904, 0x0403, 0x0503, 0x0603, 0x0807, 0x0808, 0x081a, 0x081b, 0x081c,
            0x0809, 0x080a, 0x080b, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0303, 0x0301,
            0x0302, 0x0402, 0x0502, 0x0602,
        ],
        groups: vec![4588, 29, 23, 30, 24, 25, 256, 257],
        point_formats: vec![0, 1, 2],
        alpn: vec![],
    }
}

fn main() {
    let mut url = String::from("https://127.0.0.1:14433/");
    let mut insecure = false;
    let mut openssl_shape = false;
    let mut no_profile = false;
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--insecure" => insecure = true,
            "--openssl-profile" => openssl_shape = true,
            "--no-profile" => no_profile = true,
            _ => url = arg,
        }
    }

    let config = ClientConfig {
        http2: !openssl_shape,
        http3: false,
        max_connections_per_host: 1,
        connect_timeout: Some(Duration::from_secs(5)),
        read_timeout: Some(Duration::from_secs(5)),
        handshake_timeout: Some(Duration::from_secs(5)),
        max_redirects: 0,
        user_agent: Some("Segmeris/1.0".to_string()),
        max_header_list: 1 << 20,
        max_body: 1 << 20,
        tls: Some(TlsSettings {
            roots: RootStore::new(),
            verify: !insecure,
            alpn: if openssl_shape {
                vec![]
            } else {
                vec![b"h2".to_vec(), b"http/1.1".to_vec()]
            },
            min_version: TlsVersion::Tls12,
            max_version: TlsVersion::Tls13,
            now: 0,
            identity: None,
            profile: if no_profile {
                None
            } else {
                Some(if openssl_shape {
                    openssl_style_profile()
                } else {
                    chrome_tls_profile()
                })
            },
        }),
        ..Default::default()
    };

    let client = Client::with_config(config);
    match client.execute(&url, Request::new(Method::GET, "/")) {
        Ok(response) => {
            let body = response
                .body
                .collect_limited(4096)
                .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
                .unwrap_or_default();
            println!(
                "OK status={} body={}",
                response.status.as_u16(),
                body.trim()
            );
        }
        Err(error) => println!("ERR {error}"),
    }
}
