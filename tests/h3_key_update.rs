//! RFC 9001 §6 automatic bidirectional key update over a real loopback
//! QUIC connection.
//!
//! This is a dedicated test binary so the `COURIERUST_KEY_UPDATE_PACKETS`
//! override does not leak into the other H3 tests (the override is a
//! process-global env var; a separate binary keeps it scoped).

mod common;

use courierust::courierust_body::Body;
use courierust::courierust_client::{Client, ClientConfig, TlsSettings as ClientTls};
use courierust::courierust_http::request::Request;
use courierust::courierust_server::{Server, ServerConfig, TlsSettings as ServerTls};
use std::time::Duration;

#[test]
fn h3_automatic_bidirectional_key_update_keeps_connection_alive() {
    // Force a key update after every 8 sent application packets (the
    // default is 4096); the transfer below sends far more, so both
    // directions perform several key updates.
    std::env::set_var("COURIERUST_KEY_UPDATE_PACKETS", "8");

    let server = Server::bind_with_config(
        "127.0.0.1:0",
        ServerConfig {
            http3: true,
            tls: Some(ServerTls {
                identity: common::server_identity(),
                alpn: vec![b"h3".to_vec()],
            }),
            ..Default::default()
        },
    )
    .unwrap();
    let addr = server.local_addr().unwrap();
    let handle = server
        .serve_background(|req: Request<Body>| {
            // Echo the request path as the body (a few hundred bytes,
            // so each response spans several QUIC packets).
            let path = req.uri.as_str().as_bytes().to_vec();
            courierust::courierust_http::response::Response::<Body>::with_status(200.into())
                .with_body(Body::Bytes(courierust::courierust_bytes::Bytes::from(path)))
        })
        .unwrap();
    std::mem::forget(handle);

    let client = Client::with_config(ClientConfig {
        http3: true,
        max_connections_per_host: 1,
        read_timeout: Some(Duration::from_secs(10)),
        max_body: 1 << 20,
        tls: Some(ClientTls {
            roots: common::root_store(),
            verify: true,
            alpn: vec![b"h3".to_vec()],
            now: common::NOW,
        }),
        ..Default::default()
    });

    // A single pooled QUIC connection; enough requests that both the
    // client and the server pass the (tiny) key-update threshold many
    // times, in both directions.
    for i in 0..400 {
        let resp = client
            .get(&format!("https://{addr}/key-update-{i}"))
            .unwrap_or_else(|e| panic!("request {i} after key update failed: {e}"));
        assert_eq!(resp.status.as_u16(), 200);
        let body = resp.body.collect().unwrap();
        assert_eq!(body.to_str().unwrap(), format!("/key-update-{i}"));
    }
}
