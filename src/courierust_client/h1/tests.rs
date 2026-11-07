use super::*;
use std::net::{Shutdown, TcpListener, TcpStream};

fn seeded(bytes: &[u8], cfg: &ClientConfig) -> (H1Connection, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (peer, _) = listener.accept().unwrap();
    let connection =
        H1Connection::from_stream_seeded(ConnStream::plain(client), cfg, bytes).unwrap();
    (connection, peer)
}

#[test]
fn extra_response_bytes_prevent_pool_reuse() {
    let cfg = ClientConfig::default();
    let bytes = b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nokHTTP/1.1 200 OK\r\ncontent-length: 6\r\n\r\nforged";
    let (mut connection, _peer) = seeded(bytes, &cfg);
    let response = connection.read_response(&cfg, Method::GET).unwrap();
    assert_eq!(response.body.as_bytes(), Some(&b"ok"[..]));
    assert!(
        !connection.is_reusable(),
        "unsolicited bytes must not enter the pool"
    );
    assert!(!connection.is_alive());
}

#[test]
fn a_partial_status_line_is_not_a_stale_connection_failure() {
    let cfg = ClientConfig::default();
    let (mut connection, peer) = seeded(b"HTTP/1.1 20", &cfg);
    peer.shutdown(Shutdown::Write).unwrap();
    let error = connection.read_response(&cfg, Method::GET).unwrap_err();
    assert_eq!(error.kind, ErrorKind::UnexpectedEof);
    assert!(connection.response_started(), "the peer already answered");
    assert!(
        !connection.is_stale_failure(&error),
        "partial responses must not be retried"
    );
}

#[test]
fn response_header_limit_is_enforced() {
    let cfg = ClientConfig {
        max_header_list: 8,
        ..Default::default()
    };
    let (mut connection, _peer) = seeded(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n", &cfg);
    assert_eq!(
        connection
            .read_response(&cfg, Method::GET)
            .unwrap_err()
            .kind,
        ErrorKind::Overflow
    );
    assert!(!connection.is_reusable());
}

#[test]
fn interim_response_uses_the_final_http_version() {
    let cfg = ClientConfig::default();
    let (mut connection, _peer) = seeded(
        b"HTTP/1.1 103 Early Hints\r\n\r\nHTTP/1.0 200 OK\r\ncontent-length: 0\r\n\r\n",
        &cfg,
    );
    let response = connection.read_response(&cfg, Method::GET).unwrap();
    assert_eq!(response.version, Version::HTTP_10);
    assert!(!connection.is_reusable());
}

#[test]
fn unsolicited_upgrade_is_rejected_without_reading_another_response() {
    let cfg = ClientConfig::default();
    let (mut connection, peer) = seeded(b"HTTP/1.1 101 Switching Protocols\r\n\r\n", &cfg);
    peer.shutdown(Shutdown::Write).unwrap();
    assert_eq!(
        connection
            .read_response(&cfg, Method::GET)
            .unwrap_err()
            .kind,
        ErrorKind::Protocol
    );
    assert!(!connection.is_reusable());
}

#[test]
fn informational_response_flood_is_bounded() {
    let cfg = ClientConfig::default();
    let mut bytes = b"HTTP/1.1 103 Early Hints\r\n\r\n".repeat(128);
    bytes.extend_from_slice(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n");
    let (mut connection, _peer) = seeded(&bytes, &cfg);
    assert_eq!(
        connection
            .read_response(&cfg, Method::GET)
            .unwrap_err()
            .kind,
        ErrorKind::Overflow
    );
}

#[test]
fn invalid_deadline_is_not_silently_ignored() {
    let cfg = ClientConfig {
        read_timeout: Some(Duration::ZERO),
        ..Default::default()
    };
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let socket = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let _peer = listener.accept().unwrap();
    assert!(H1Connection::from_stream_seeded(ConnStream::plain(socket), &cfg, &[]).is_err());
}

#[test]
fn declaring_an_absent_request_body_fails_before_writing() {
    let cfg = ClientConfig::default();
    let (mut connection, peer) = seeded(&[], &cfg);
    peer.shutdown(Shutdown::Write).unwrap();
    let mut request = Request::new(Method::POST, "/");
    request.headers.insert(
        HeaderName::from_static("content-length"),
        HeaderValue::from_static("4"),
    );
    let error = connection
        .send(&request, &cfg, "localhost", false)
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Protocol);
    peer.set_nonblocking(true).unwrap();
    assert_eq!(
        peer.peek(&mut [0]).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

fn close_delimited_tls_reply(
    version: crate::courierust_tls::TlsVersion,
    notify: bool,
) -> Result<Response<Body>> {
    use crate::courierust_client::{Client, TlsSettings};
    use crate::courierust_tls::{testdata, ServerConfig, TlsAcceptor};

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let peer = std::thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        courierust_net::configure(&socket, Some(Duration::from_secs(5))).unwrap();
        let acceptor = TlsAcceptor::new(ServerConfig {
            identity: testdata::server_identity(),
            alpn: vec![b"http/1.1".to_vec()],
            min_version: version,
            max_version: version,
            ..Default::default()
        });
        let mut tls = acceptor.accept(&socket, &socket).unwrap();
        let mut request = BufReader::new(&mut tls, 1024);
        while request.read_until(b'\n', 4096).unwrap() != b"\r\n" {}
        drop(request);
        tls.write_all(b"HTTP/1.1 200 OK\r\nconnection: close\r\n\r\npayload")
            .unwrap();
        if notify {
            tls.close_notify().unwrap();
        }
    });
    let client = Client::with_config(ClientConfig {
        read_timeout: Some(Duration::from_secs(5)),
        tls: Some(TlsSettings {
            roots: testdata::root_store(),
            now: testdata::NOW,
            min_version: version,
            max_version: version,
            alpn: vec![b"http/1.1".to_vec()],
            ..Default::default()
        }),
        ..Default::default()
    });
    let response = client.get(&format!("https://{addr}/"));
    peer.join().unwrap();
    response
}

#[test]
fn a_close_delimited_tls_body_requires_authenticated_shutdown() {
    use crate::courierust_tls::TlsVersion;
    for version in [TlsVersion::Tls12, TlsVersion::Tls13] {
        let error = close_delimited_tls_reply(version, false).unwrap_err();
        assert_eq!(error.kind, ErrorKind::UnexpectedEof);
    }
}

#[test]
fn a_close_delimited_tls_body_accepts_close_notify() {
    use crate::courierust_tls::TlsVersion;
    for version in [TlsVersion::Tls12, TlsVersion::Tls13] {
        let response = close_delimited_tls_reply(version, true).unwrap();
        assert_eq!(response.body.as_bytes(), Some(&b"payload"[..]));
    }
}
