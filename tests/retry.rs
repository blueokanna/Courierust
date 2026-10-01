//! Retry behaviour: what is retried, what is not, and how many times the
//! server is actually asked.
//!
//! The server here drops a configurable number of connections before writing
//! a byte, which is the one failure the client can *know* did not complete —
//! and therefore the only kind a policy is allowed to repeat.

use courierust::courierust_body::Body;
use courierust::courierust_bytes::Bytes;
use courierust::courierust_client::{Client, ClientConfig, RetryPolicy};
use courierust::courierust_http::method::Method;
use courierust::courierust_http::request::Request;
use courierust::courierust_http::uri::Url;
use courierust::courierust_server::reverse_proxy::{Matcher, ReverseProxy};
use courierust::courierust_server::{Server, ServerConfig};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

fn read_head(stream: &mut TcpStream) -> usize {
    let mut head = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    loop {
        match stream.read(&mut byte) {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                head.push(byte[0]);
                if head.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
        }
    }
    head.len()
}

/// What the serve loop answers once it stops dropping connections.
#[derive(Clone, Copy)]
enum Answer {
    /// A fixed `200` with this body.
    Ok(&'static str),
    /// A status line no client can parse.
    Garbage,
}

struct FlakyServer {
    addr: SocketAddr,
    connections: Arc<AtomicUsize>,
    _listener: TcpListener,
}

impl FlakyServer {
    fn start(failures: usize, answer: Answer) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let connections = Arc::new(AtomicUsize::new(0));
        let accept = listener.try_clone().expect("clone");
        let counter = connections.clone();
        std::thread::spawn(move || {
            for stream in accept.incoming() {
                let Ok(mut stream) = stream else { break };
                let seen = counter.fetch_add(1, Ordering::SeqCst);
                if seen < failures {
                    // Gone before the response existed: a transport failure.
                    drop(stream);
                    continue;
                }
                std::thread::spawn(move || {
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                    read_head(&mut stream);
                    let bytes: Vec<u8> = match answer {
                        Answer::Ok(body) => format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        )
                        .into_bytes(),
                        Answer::Garbage => b"not-http\r\n\r\n".to_vec(),
                    };
                    let _ = stream.write_all(&bytes);
                    let _ = stream.flush();
                    let _ = stream.shutdown(std::net::Shutdown::Write);
                });
            }
        });
        Self {
            addr,
            connections,
            _listener: listener,
        }
    }

    fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }
}

fn policy(attempts: u32, retry_non_idempotent: bool) -> RetryPolicy {
    RetryPolicy {
        attempts,
        base_backoff: Duration::from_millis(10),
        max_backoff: Duration::from_millis(20),
        retry_non_idempotent,
    }
}

fn client(retry: RetryPolicy, http2: bool) -> Client {
    Client::with_config(ClientConfig {
        retry: Some(retry),
        http2,
        connect_timeout: Some(Duration::from_secs(2)),
        read_timeout: Some(Duration::from_secs(2)),
        ..Default::default()
    })
}

#[test]
fn a_transport_failure_is_retried_within_the_budget() {
    let server = FlakyServer::start(2, Answer::Ok("retried"));
    let client = client(policy(3, false), false);
    let resp = client.get(&format!("{}/", server.url())).unwrap();
    assert_eq!(resp.body.collect().unwrap().to_str().unwrap(), "retried");
    assert_eq!(
        server.connections(),
        3,
        "two dropped connections and the one that answered"
    );
}

#[test]
fn a_post_is_not_retried_by_default() {
    let server = FlakyServer::start(1, Answer::Ok("never reached"));
    let client = client(policy(3, false), false);
    let error = client
        .post(&format!("{}/", server.url()), "payload".to_string())
        .expect_err("a duplicate write is worse than a reported failure");
    // Which transport kind it is depends on the platform's idea of "the
    // connection went away": Windows reports an abort as `Canceled`, Linux
    // usually as `Io` or `UnexpectedEof`.
    assert!(
        matches!(
            error.kind,
            courierust::ErrorKind::Io
                | courierust::ErrorKind::UnexpectedEof
                | courierust::ErrorKind::Canceled
        ),
        "unexpected error: {error}"
    );
    assert_eq!(
        server.connections(),
        1,
        "the peer must not be asked to write the same thing twice"
    );
}

#[test]
fn retry_non_idempotent_opts_into_repeating_a_post() {
    let server = FlakyServer::start(1, Answer::Ok("accepted"));
    let client = client(policy(3, true), false);
    let resp = client
        .post(&format!("{}/", server.url()), "payload".to_string())
        .unwrap();
    assert_eq!(resp.body.collect().unwrap().to_str().unwrap(), "accepted");
    assert_eq!(server.connections(), 2);
}

#[test]
fn one_attempt_means_one_attempt() {
    let server = FlakyServer::start(1, Answer::Ok("unused"));
    let client = client(policy(1, true), false);
    client
        .get(&format!("{}/", server.url()))
        .expect_err("must fail");
    assert_eq!(server.connections(), 1);
}

#[test]
fn a_reverse_proxy_never_replays_an_upstream_request() {
    let upstream = FlakyServer::start(1, Answer::Ok("must not be reached"));
    let upstream_url = upstream.url();
    let proxy_client = client(policy(3, true), false);
    let server = Server::bind_with_config("127.0.0.1:0", ServerConfig::default()).unwrap();
    let proxy_addr = server.local_addr().unwrap();
    let handle = server
        .serve_background(ReverseProxy::new(proxy_client).route(
            Matcher::Prefix("/".to_string()),
            Url::parse(&upstream_url).unwrap(),
        ))
        .unwrap();
    std::mem::forget(handle);

    let response = Client::new()
        .get(&format!("http://{proxy_addr}/write"))
        .unwrap();
    assert_eq!(
        response.status.as_u16(),
        502,
        "the proxy reports the transport failure instead of retrying it"
    );
    assert_eq!(
        upstream.connections(),
        1,
        "even an explicitly retrying client must not make a proxy replay the request"
    );
}

#[test]
fn a_protocol_error_is_not_retried() {
    // Repeating a request against a peer that answers the same way every
    // time only burns the budget: the failure is a property of the peer or
    // of the request, not of this attempt.
    let server = FlakyServer::start(0, Answer::Garbage);
    let client = client(policy(3, false), false);
    let error = client
        .get(&format!("{}/", server.url()))
        .expect_err("must fail");
    assert_eq!(error.kind, courierust::ErrorKind::Protocol, "{error}");
    assert_eq!(server.connections(), 1, "one attempt, one connection");
}

#[test]
fn a_streaming_body_is_not_replayed() {
    // A `Body::Channel` is consumed by the attempt that read it, so a retry
    // would send a *different* request. The rule is observable in the
    // connection count: the same server and the same policy retry a
    // buffered body and refuse to retry a streamed one.
    let buffered = FlakyServer::start(1, Answer::Ok("unused"));
    let client = client(policy(3, true), true);
    let mut req = Request::<Body>::new(Method::PUT, "/");
    req.body = Body::Bytes(Bytes::from_static(b"buffered"));
    let _ = client.execute(&format!("{}/", buffered.url()), req);
    assert!(
        buffered.connections() >= 2,
        "a buffered body can be replayed, so it is: {}",
        buffered.connections()
    );

    let streamed = FlakyServer::start(1, Answer::Ok("unused"));
    let (tx, body) = courierust::courierust_body::channel();
    std::thread::spawn(move || {
        let _ = tx.send(Bytes::from_static(b"streamed"));
    });
    let mut req = Request::<Body>::new(Method::PUT, "/");
    req.body = body;
    let _ = client.execute(&format!("{}/", streamed.url()), req);
    assert_eq!(
        streamed.connections(),
        1,
        "a streamed body has no second copy, so there is no second attempt"
    );
}
