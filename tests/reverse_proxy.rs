//! Reverse-proxy behaviour, end to end: a real proxy server in front of a
//! real upstream.

use courierust::courierust_body::Body;
use courierust::courierust_client::{Client, ClientConfig};
use courierust::courierust_http::header::{HeaderName, HeaderValue};
use courierust::courierust_http::method::Method;
use courierust::courierust_http::request::Request;
use courierust::courierust_http::response::Response;
use courierust::courierust_http::uri::Url;
use courierust::courierust_server::reverse_proxy::{
    Balance, HealthPolicy, Matcher, ReverseProxy, Upstream,
};
use courierust::courierust_server::{Server, ServerConfig};
use courierust::courierust_ws::IpNet;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// What the upstream saw.
#[derive(Debug, Clone, Default)]
struct Seen {
    target: String,
    method: String,
    body: String,
    headers: Vec<(String, String)>,
}

impl Seen {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// An upstream that records the request and echoes the target back.
fn spawn_upstream(hits: Arc<AtomicUsize>, seen: Arc<Mutex<Option<Seen>>>) -> String {
    let server = Server::bind_with_config("127.0.0.1:0", ServerConfig::default()).unwrap();
    let addr = server.local_addr().unwrap();
    let handle = server
        .serve_background(move |req: Request<Body>| {
            hits.fetch_add(1, Ordering::SeqCst);
            let mut record = Seen {
                target: req.uri.as_str().to_string(),
                method: req.method.as_str().to_string(),
                ..Default::default()
            };
            for (name, value) in req.headers.iter() {
                record.headers.push((
                    name.as_str().to_string(),
                    String::from_utf8_lossy(value.as_bytes()).into_owned(),
                ));
            }
            record.body =
                String::from_utf8_lossy(&req.body.collect().unwrap_or_default()).into_owned();
            let echoed = record.target.clone();
            *seen.lock().unwrap() = Some(record);

            let mut resp = Response::<Body>::with_status(200.into());
            // Hop-by-hop on the response side: it must not reach the client.
            resp.headers.insert(
                HeaderName::from_lowercase("keep-alive"),
                HeaderValue::from_static("timeout=5"),
            );
            resp.headers.insert(
                HeaderName::from_lowercase("x-upstream"),
                HeaderValue::from_static("yes"),
            );
            resp.body = Body::Bytes(courierust::courierust_bytes::Bytes::from(
                echoed.into_bytes(),
            ));
            resp
        })
        .unwrap();
    std::mem::forget(handle);
    format!("http://{addr}")
}

/// A proxy built by `routes`, which is handed the proxy's own base URL — the
/// authority a client will actually send in `Host`.
fn spawn_proxy(routes: impl FnOnce(&str) -> ReverseProxy) -> String {
    let server = Server::bind_with_config("127.0.0.1:0", ServerConfig::default()).unwrap();
    let addr = server.local_addr().unwrap();
    let base = format!("http://{addr}");
    let proxy = routes(&base);
    let handle = server.serve_background(proxy).unwrap();
    std::mem::forget(handle);
    base
}

fn prefix_route(pattern: &str) -> Matcher {
    Matcher::Prefix(pattern.to_string())
}

/// An upstream that counts its hits and answers after `delay`.
fn spawn_counting_upstream(hits: Arc<AtomicUsize>, delay: Duration) -> String {
    let server = Server::bind_with_config("127.0.0.1:0", ServerConfig::default()).unwrap();
    let addr = server.local_addr().unwrap();
    let handle = server
        .serve_background(move |_req: Request<Body>| {
            hits.fetch_add(1, Ordering::SeqCst);
            if !delay.is_zero() {
                std::thread::sleep(delay);
            }
            let mut resp = Response::<Body>::with_status(200.into());
            resp.body = Body::Bytes(courierust::courierust_bytes::Bytes::from(b"ok".to_vec()));
            resp
        })
        .unwrap();
    std::mem::forget(handle);
    format!("http://{addr}")
}

/// A port nothing is listening on: bound, read and released, so a connection
/// to it is refused rather than left hanging.
fn closed_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

/// A proxy whose server is given an explicit number of event workers.
///
/// The tests that need two requests in flight at once use this: the default
/// is one worker per core, and on a single-core machine the proxy would serve
/// the second request only after the first one finished, which is not a
/// property of the proxy but of the machine running the test.
fn spawn_concurrent_proxy(workers: usize, routes: impl FnOnce(&str) -> ReverseProxy) -> String {
    let config = ServerConfig {
        event_workers: workers,
        ..ServerConfig::default()
    };
    let server = Server::bind_with_config("127.0.0.1:0", config).unwrap();
    let addr = server.local_addr().unwrap();
    let base = format!("http://{addr}");
    let proxy = routes(&base);
    let handle = server.serve_background(proxy).unwrap();
    std::mem::forget(handle);
    base
}

#[test]
fn a_prefix_route_replaces_the_prefix_with_the_upstream_path() {
    let hits = Arc::new(AtomicUsize::new(0));
    let seen = Arc::new(Mutex::new(None));
    let upstream = spawn_upstream(hits.clone(), seen.clone());
    let proxy = spawn_proxy(move |_| {
        ReverseProxy::new(Client::new()).route(prefix_route("/api"), Url::parse(&upstream).unwrap())
    });
    let client = Client::new();

    let resp = client.get(&format!("{proxy}/api/v1/items?q=2")).unwrap();
    assert_eq!(resp.status.as_u16(), 200);
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    let seen = seen
        .lock()
        .unwrap()
        .clone()
        .expect("the upstream was asked");
    assert_eq!(
        seen.target, "/v1/items?q=2",
        "the matched prefix is consumed and the query is untouched"
    );
    assert_eq!(
        resp.body.collect().unwrap().to_str().unwrap(),
        "/v1/items?q=2"
    );
}

#[test]
fn an_upstream_path_becomes_the_new_prefix() {
    let hits = Arc::new(AtomicUsize::new(0));
    let seen = Arc::new(Mutex::new(None));
    let upstream = format!("{}/base", spawn_upstream(hits.clone(), seen.clone()));
    let proxy = spawn_proxy(move |_| {
        ReverseProxy::new(Client::new()).route(prefix_route("/api"), Url::parse(&upstream).unwrap())
    });
    let client = Client::new();

    client.get(&format!("{proxy}/api/x")).unwrap();
    assert_eq!(seen.lock().unwrap().clone().unwrap().target, "/base/x");
    client.get(&format!("{proxy}/api/")).unwrap();
    assert_eq!(
        seen.lock().unwrap().clone().unwrap().target,
        "/base/",
        "one slash, not two, whatever both sides brought"
    );
}

#[test]
fn a_prefix_is_a_segment_boundary_not_a_byte_prefix() {
    let hits = Arc::new(AtomicUsize::new(0));
    let seen = Arc::new(Mutex::new(None));
    let upstream = spawn_upstream(hits.clone(), seen.clone());
    let proxy = spawn_proxy(move |_| {
        ReverseProxy::new(Client::new()).route(prefix_route("/api"), Url::parse(&upstream).unwrap())
    });
    let client = Client::new();

    let resp = client.get(&format!("{proxy}/apifoo")).unwrap();
    assert_eq!(resp.status.as_u16(), 404, "`/apifoo` is not under `/api`");
    assert_eq!(hits.load(Ordering::SeqCst), 0, "the upstream stayed quiet");

    // `/api` and `/api/` are both under the prefix, and both become the
    // upstream's root.
    client.get(&format!("{proxy}/api")).unwrap();
    assert_eq!(seen.lock().unwrap().clone().unwrap().target, "/");
    client.get(&format!("{proxy}/api/")).unwrap();
    assert_eq!(seen.lock().unwrap().clone().unwrap().target, "/");
    assert_eq!(hits.load(Ordering::SeqCst), 2);
}

#[test]
fn the_longest_prefix_wins() {
    let general_hits = Arc::new(AtomicUsize::new(0));
    let general_seen = Arc::new(Mutex::new(None));
    let general = spawn_upstream(general_hits.clone(), general_seen.clone());
    let api_hits = Arc::new(AtomicUsize::new(0));
    let api_seen = Arc::new(Mutex::new(None));
    let api = spawn_upstream(api_hits.clone(), api_seen.clone());

    let proxy = spawn_proxy(move |_| {
        ReverseProxy::new(Client::new())
            .route(prefix_route("/"), Url::parse(&general).unwrap())
            .route(prefix_route("/api"), Url::parse(&api).unwrap())
    });
    let client = Client::new();
    client.get(&format!("{proxy}/api/x")).unwrap();
    client.get(&format!("{proxy}/other")).unwrap();

    assert_eq!(api_hits.load(Ordering::SeqCst), 1, "`/api` owns `/api/x`");
    assert_eq!(
        general_hits.load(Ordering::SeqCst),
        1,
        "the catch-all gets the rest"
    );
}

#[test]
fn a_host_route_matches_the_host_header() {
    let hits = Arc::new(AtomicUsize::new(0));
    let seen = Arc::new(Mutex::new(None));
    let upstream = spawn_upstream(hits.clone(), seen.clone());
    // The client derives `Host` from the URL, so a host route has to name the
    // authority the client will send — this proxy's own.
    let routed = upstream.clone();
    let proxy = spawn_proxy(move |base| {
        ReverseProxy::new(Client::new()).route(
            Matcher::Host(base.trim_start_matches("http://").to_string()),
            Url::parse(&routed).unwrap(),
        )
    });
    let client = Client::new();

    let resp = client.get(&format!("{proxy}/x")).unwrap();
    assert_eq!(resp.status.as_u16(), 200);
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    assert_eq!(seen.lock().unwrap().clone().unwrap().target, "/x");

    // The same upstream behind a route that wants a different host: the
    // request does not match, and nothing is forwarded.
    let upstream_url = upstream.clone();
    let other = spawn_proxy(move |_| {
        ReverseProxy::new(Client::new()).route(
            Matcher::Host("api.internal:80".to_string()),
            Url::parse(&upstream_url).unwrap(),
        )
    });
    let resp = client.get(&format!("{other}/x")).unwrap();
    assert_eq!(resp.status.as_u16(), 404, "a different host is not routed");
}

#[test]
fn forwarding_metadata_is_added_and_appended_never_rewritten() {
    let hits = Arc::new(AtomicUsize::new(0));
    let seen = Arc::new(Mutex::new(None));
    let upstream = spawn_upstream(hits.clone(), seen.clone());
    let routed = upstream.clone();
    let proxy = spawn_proxy(move |_| {
        ReverseProxy::new(Client::new())
            // The test connects from loopback, and a chain is only preserved
            // from a peer the proxy was told to believe. That is the other
            // half of this test's subject, and it has its own case below.
            .trust([IpNet::parse("127.0.0.1").expect("a host route")])
            .route(prefix_route("/"), Url::parse(&routed).unwrap())
    });
    let client = Client::new();

    let mut req = Request::<Body>::new(Method::GET, "/x");
    req.headers.insert(
        HeaderName::from_lowercase("via"),
        HeaderValue::from_static("1.1 first-proxy"),
    );
    req.headers.insert(
        HeaderName::from_lowercase("x-forwarded-for"),
        HeaderValue::from_static("203.0.113.7"),
    );
    client.execute(&format!("{proxy}/x"), req).unwrap();

    let seen = seen.lock().unwrap().clone().unwrap();
    let via = seen.header("via").expect("Via was added");
    assert!(
        via.starts_with("1.1 first-proxy, 1.1 courierust/"),
        "the chain is preserved and ours appended, got `{via}`"
    );
    assert_eq!(
        seen.header("x-forwarded-for"),
        Some("203.0.113.7, 127.0.0.1"),
        "the original is kept and the peer appended"
    );
    assert_eq!(seen.header("x-forwarded-proto"), Some("http"));
    assert_eq!(
        seen.header("x-forwarded-host"),
        Some(proxy.trim_start_matches("http://"))
    );
    assert_eq!(
        seen.header("host"),
        Some(upstream.trim_start_matches("http://")),
        "the upstream is addressed by its own name"
    );
}

#[test]
fn hop_by_hop_headers_never_cross_the_proxy() {
    let hits = Arc::new(AtomicUsize::new(0));
    let seen = Arc::new(Mutex::new(None));
    let upstream = spawn_upstream(hits.clone(), seen.clone());
    let proxy = spawn_proxy(move |_| {
        ReverseProxy::new(Client::new()).route(prefix_route("/"), Url::parse(&upstream).unwrap())
    });
    let client = Client::new();

    let mut req = Request::<Body>::new(Method::GET, "/x");
    for (name, value) in [
        ("keep-alive", "timeout=5"),
        ("te", "trailers"),
        ("proxy-authorization", "Basic c2VjcmV0"),
        ("proxy-connection", "keep-alive"),
    ] {
        req.headers.insert(
            HeaderName::from_lowercase(name),
            HeaderValue::from_static(value),
        );
    }
    let resp = client.execute(&format!("{proxy}/x"), req).unwrap();

    let seen = seen.lock().unwrap().clone().unwrap();
    for name in [
        "keep-alive",
        "te",
        "proxy-authorization",
        "proxy-connection",
    ] {
        assert_eq!(
            seen.header(name),
            None,
            "`{name}` is hop-by-hop and must not be relayed"
        );
    }
    assert!(
        resp.headers.get("keep-alive").is_none(),
        "the upstream's hop-by-hop response header must not reach the client either"
    );
    assert_eq!(
        resp.headers.get("x-upstream").unwrap().to_str().unwrap(),
        "yes",
        "end-to-end headers do survive"
    );
}

#[test]
fn connection_named_headers_never_cross_the_proxy() {
    let hits = Arc::new(AtomicUsize::new(0));
    let seen = Arc::new(Mutex::new(None));
    let upstream = spawn_upstream(hits.clone(), seen.clone());
    let proxy = spawn_proxy(move |_| {
        ReverseProxy::new(Client::new()).route(prefix_route("/"), Url::parse(&upstream).unwrap())
    });
    let authority = proxy.trim_start_matches("http://");
    let mut socket = TcpStream::connect(authority).expect("connect to the proxy");
    socket
        .write_all(
            format!(
                "GET /x HTTP/1.1\r\nHost: {authority}\r\nConnection: x-this-hop-only\r\n\
                 X-This-Hop-Only: must-not-reach-upstream\r\n\r\n"
            )
            .as_bytes(),
        )
        .expect("write request");
    socket.flush().expect("flush request");
    let mut response = [0u8; 128];
    assert!(socket.read(&mut response).expect("read response") > 0);

    assert_eq!(hits.load(Ordering::SeqCst), 1);
    assert_eq!(
        seen.lock()
            .unwrap()
            .clone()
            .unwrap()
            .header("x-this-hop-only"),
        None,
        "a field nominated by Connection is hop-by-hop even when its name is not standard"
    );
}

#[test]
fn a_body_is_forwarded_in_both_directions() {
    let hits = Arc::new(AtomicUsize::new(0));
    let seen = Arc::new(Mutex::new(None));
    let upstream = spawn_upstream(hits.clone(), seen.clone());
    let proxy = spawn_proxy(move |_| {
        ReverseProxy::new(Client::new()).route(prefix_route("/"), Url::parse(&upstream).unwrap())
    });
    let client = Client::new();

    let resp = client
        .post(&format!("{proxy}/submit"), "hello upstream".to_string())
        .unwrap();
    assert_eq!(resp.status.as_u16(), 200);
    let seen = seen.lock().unwrap().clone().unwrap();
    assert_eq!(seen.method, "POST");
    assert_eq!(seen.body, "hello upstream");
    assert_eq!(seen.target, "/submit");
}

#[test]
fn an_upgrade_request_is_refused_rather_than_forwarded() {
    let hits = Arc::new(AtomicUsize::new(0));
    let seen = Arc::new(Mutex::new(None));
    let upstream = spawn_upstream(hits.clone(), seen.clone());
    let proxy = spawn_proxy(move |_| {
        ReverseProxy::new(Client::new()).route(prefix_route("/"), Url::parse(&upstream).unwrap())
    });

    // Written by hand: this crate's own client strips `Connection`/`Upgrade`
    // (they are hop-by-hop, and it has no upgrade support), so the only way
    // to put one on the wire is to be the peer.
    let authority = proxy.trim_start_matches("http://");
    let mut socket = TcpStream::connect(authority).expect("connect to the proxy");
    socket
        .write_all(
            format!(
                "GET /ws HTTP/1.1\r\nHost: {authority}\r\nConnection: Upgrade\r\n\
                 Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\n\
                 Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
            )
            .as_bytes(),
        )
        .expect("write the upgrade request");
    socket.flush().unwrap();
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") && head.len() < 512 {
        if socket.read(&mut byte).unwrap_or(0) == 0 {
            break;
        }
        head.push(byte[0]);
    }
    let status = String::from_utf8_lossy(&head);
    assert!(
        status.starts_with("HTTP/1.1 501"),
        "the failure has to be visible, not a mysteriously broken upgrade: {status}"
    );
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}

#[test]
fn an_unreachable_upstream_is_a_gateway_error() {
    // Bind and drop, so the port is free.
    let dead = Server::bind("127.0.0.1:0").unwrap();
    let dead_addr = dead.local_addr().unwrap();
    drop(dead);
    let proxy = spawn_proxy(move |_| {
        ReverseProxy::new(Client::new()).route(
            prefix_route("/"),
            Url::parse(&format!("http://{dead_addr}")).unwrap(),
        )
    });
    let client = Client::new();
    let resp = client.get(&format!("{proxy}/x")).unwrap();
    assert_eq!(resp.status.as_u16(), 502);
    assert!(
        !resp.body.collect().unwrap().is_empty(),
        "a gateway error must say what failed"
    );
}

#[test]
fn round_robin_gives_every_upstream_the_same_share() {
    let first = Arc::new(AtomicUsize::new(0));
    let second = Arc::new(AtomicUsize::new(0));
    let a = spawn_counting_upstream(first.clone(), Duration::ZERO);
    let b = spawn_counting_upstream(second.clone(), Duration::ZERO);
    let proxy = spawn_proxy(move |_| {
        ReverseProxy::new(Client::new()).route_all(
            prefix_route("/"),
            [Url::parse(&a).unwrap(), Url::parse(&b).unwrap()],
        )
    });
    let client = Client::new();
    for _ in 0..6 {
        let resp = client.get(&format!("{proxy}/x")).unwrap();
        assert_eq!(resp.status.as_u16(), 200);
    }
    assert_eq!(first.load(Ordering::SeqCst), 3);
    assert_eq!(second.load(Ordering::SeqCst), 3);
}

#[test]
fn an_upstream_that_cannot_be_reached_is_taken_out_of_the_rotation() {
    // The live one is bound first, so the port released below cannot be it.
    let hits = Arc::new(AtomicUsize::new(0));
    let live = spawn_counting_upstream(hits.clone(), Duration::ZERO);
    let dead = format!("http://127.0.0.1:{}", closed_port());
    let proxy = spawn_proxy(move |_| {
        ReverseProxy::new(Client::new())
            .health(HealthPolicy {
                failures: 1,
                cooldown: Duration::from_secs(30),
            })
            .route_all(
                prefix_route("/"),
                [Url::parse(&dead).unwrap(), Url::parse(&live).unwrap()],
            )
    });
    let client = Client::new();
    // The first request lands on the dead upstream and fails.
    assert_eq!(
        client.get(&format!("{proxy}/x")).unwrap().status.as_u16(),
        502
    );
    // Round robin would send every other request back to it; ejection is what
    // makes the next two land on the one that is up.
    for _ in 0..2 {
        assert_eq!(
            client.get(&format!("{proxy}/x")).unwrap().status.as_u16(),
            200
        );
    }
    assert_eq!(hits.load(Ordering::SeqCst), 2);
}

#[test]
fn ejection_can_be_turned_off() {
    let hits = Arc::new(AtomicUsize::new(0));
    let live = spawn_counting_upstream(hits.clone(), Duration::ZERO);
    let dead = format!("http://127.0.0.1:{}", closed_port());
    let proxy = spawn_proxy(move |_| {
        ReverseProxy::new(Client::new())
            .health(HealthPolicy {
                failures: 0,
                cooldown: Duration::from_secs(30),
            })
            .route_all(
                prefix_route("/"),
                [Url::parse(&dead).unwrap(), Url::parse(&live).unwrap()],
            )
    });
    let client = Client::new();
    let statuses: Vec<u16> = (0..3)
        .map(|_| client.get(&format!("{proxy}/x")).unwrap().status.as_u16())
        .collect();
    assert_eq!(
        statuses,
        vec![502, 200, 502],
        "with ejection off, every second request still goes to the dead upstream"
    );
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}

#[test]
fn a_base_query_is_prepended_to_the_requests_own() {
    let hits = Arc::new(AtomicUsize::new(0));
    let seen = Arc::new(Mutex::new(None));
    let upstream = format!(
        "{}/base?token=1",
        spawn_upstream(hits.clone(), seen.clone())
    );
    let proxy = spawn_proxy(move |_| {
        ReverseProxy::new(Client::new()).route(prefix_route("/api"), Url::parse(&upstream).unwrap())
    });
    let client = Client::new();

    client.get(&format!("{proxy}/api/x?q=2")).unwrap();
    assert_eq!(
        seen.lock().unwrap().clone().unwrap().target,
        "/base/x?token=1&q=2",
        "a query on the base is a parameter, not part of the path"
    );
}

#[test]
fn an_upstream_redirect_is_relayed_not_followed() {
    let target_hits = Arc::new(AtomicUsize::new(0));
    let target = spawn_counting_upstream(target_hits.clone(), Duration::ZERO);
    let redirect_hits = Arc::new(AtomicUsize::new(0));
    let redirect_server = Server::bind_with_config("127.0.0.1:0", ServerConfig::default()).unwrap();
    let redirect_addr = redirect_server.local_addr().unwrap();
    let location = format!("{target}/private");
    let redirect_hits_for_handler = redirect_hits.clone();
    let handle = redirect_server
        .serve_background(move |_req: Request<Body>| {
            redirect_hits_for_handler.fetch_add(1, Ordering::SeqCst);
            let mut resp = Response::<Body>::with_status(302.into());
            resp.headers.insert(
                HeaderName::from_lowercase("location"),
                HeaderValue::from_bytes(location.as_bytes()).unwrap(),
            );
            resp
        })
        .unwrap();
    std::mem::forget(handle);
    let redirect = format!("http://{redirect_addr}");
    let proxy = spawn_proxy(move |_| {
        ReverseProxy::new(Client::new()).route(prefix_route("/"), Url::parse(&redirect).unwrap())
    });

    let client = Client::with_config(ClientConfig {
        max_redirects: 0,
        ..Default::default()
    });
    let resp = client.get(&format!("{proxy}/public")).unwrap();
    assert_eq!(
        resp.status.as_u16(),
        302,
        "the proxy must relay the response"
    );
    assert_eq!(
        redirect_hits.load(Ordering::SeqCst),
        1,
        "the upstream received the original request once"
    );
    assert_eq!(
        target_hits.load(Ordering::SeqCst),
        0,
        "a Location header must never make the proxy request another origin"
    );
}

#[test]
fn least_connections_sends_nothing_to_the_upstream_that_is_still_busy() {
    let slow = Arc::new(AtomicUsize::new(0));
    let quick = Arc::new(AtomicUsize::new(0));
    let a = spawn_counting_upstream(slow.clone(), Duration::from_millis(2000));
    let b = spawn_counting_upstream(quick.clone(), Duration::ZERO);
    let proxy = spawn_concurrent_proxy(8, move |_| {
        ReverseProxy::new(Client::new()).balanced(
            prefix_route("/"),
            Balance::LeastConnections,
            [Url::parse(&a).unwrap(), Url::parse(&b).unwrap()],
        )
    });

    // The first request takes the slow upstream and holds it for two seconds.
    let url = format!("{proxy}/x");
    let occupied = std::thread::spawn(move || Client::new().get(&url));
    std::thread::sleep(Duration::from_millis(300));

    let client = Client::new();
    for _ in 0..3 {
        assert_eq!(
            client.get(&format!("{proxy}/x")).unwrap().status.as_u16(),
            200
        );
    }
    assert_eq!(
        quick.load(Ordering::SeqCst),
        3,
        "round robin would have sent the third request back to the busy upstream"
    );
    assert_eq!(slow.load(Ordering::SeqCst), 1);
    assert_eq!(occupied.join().unwrap().unwrap().status.as_u16(), 200);
}

#[test]
fn an_upstream_at_its_in_flight_limit_is_refused_not_queued() {
    let hits = Arc::new(AtomicUsize::new(0));
    let upstream = spawn_counting_upstream(hits.clone(), Duration::from_millis(2000));
    let proxy = spawn_concurrent_proxy(8, move |_| {
        let limited = Upstream::limited(Url::parse(&upstream).unwrap(), 1);
        ReverseProxy::new(Client::new()).route_all(prefix_route("/"), [limited])
    });

    let url = format!("{proxy}/x");
    let occupied = std::thread::spawn(move || Client::new().get(&url));
    std::thread::sleep(Duration::from_millis(300));

    let resp = Client::new().get(&format!("{proxy}/x")).unwrap();
    assert_eq!(resp.status.as_u16(), 503);
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "the second request never reached the upstream"
    );
    let body = resp.body.collect().unwrap();
    assert!(
        body.to_str()
            .unwrap_or_default()
            .contains("in-flight limit"),
        "the refusal says which limit was hit: {:?}",
        body.to_str()
    );
    assert_eq!(occupied.join().unwrap().unwrap().status.as_u16(), 200);

    // And once the slot is free, traffic flows again.
    assert_eq!(
        Client::new()
            .get(&format!("{proxy}/x"))
            .unwrap()
            .status
            .as_u16(),
        200
    );
    assert_eq!(hits.load(Ordering::SeqCst), 2);
}

#[test]
fn a_chain_from_an_untrusted_peer_is_replaced_not_relayed() {
    let hits = Arc::new(AtomicUsize::new(0));
    let seen = Arc::new(Mutex::new(None));
    let upstream = spawn_upstream(hits.clone(), seen.clone());
    // No `trust`: the default, and the only safe one. A proxy that has not
    // been told who is in front of it cannot tell a load balancer's chain
    // from a client's forgery.
    let proxy = spawn_proxy(move |_| {
        ReverseProxy::new(Client::new()).route(prefix_route("/"), Url::parse(&upstream).unwrap())
    });

    let mut req = Request::<Body>::new(Method::GET, "/x");
    req.headers.insert(
        HeaderName::from_lowercase("x-forwarded-for"),
        HeaderValue::from_static("203.0.113.7, 198.51.100.4"),
    );
    Client::new().execute(&format!("{proxy}/x"), req).unwrap();

    let seen = seen.lock().unwrap().clone().unwrap();
    assert_eq!(
        seen.header("x-forwarded-for"),
        Some("127.0.0.1"),
        "a client-written chain must not become the next hop's idea of who called"
    );
}

#[test]
fn the_body_limit_applies_in_both_directions() {
    let hits = Arc::new(AtomicUsize::new(0));
    let seen = Arc::new(Mutex::new(None));
    let upstream = spawn_upstream(hits.clone(), seen.clone());
    let routed = upstream.clone();
    let proxy = spawn_proxy(move |_| {
        ReverseProxy::new(Client::new())
            .body_limit(4)
            .route(prefix_route("/"), Url::parse(&routed).unwrap())
    });
    let client = Client::new();

    // The upstream echoes the target, so "/xxxxx" comes back as six bytes.
    let resp = client.get(&format!("{proxy}/xxxxx")).unwrap();
    assert_eq!(resp.status.as_u16(), 502);
    let body = resp.body.collect().unwrap();
    assert!(
        body.to_str().unwrap_or_default().contains("limit"),
        "the refusal names the limit that was hit: {:?}",
        body.to_str()
    );
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    // A request body over the limit is refused before it is forwarded: the
    // server may have read it already, but the limit here is the route's.
    let mut req = Request::<Body>::new(Method::POST, "/x");
    req.body = Body::Bytes(courierust::courierust_bytes::Bytes::from(b"12345".to_vec()));
    let resp = client.execute(&format!("{proxy}/x"), req).unwrap();
    assert_eq!(resp.status.as_u16(), 413);
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "the oversized request never reached the upstream"
    );
}

#[test]
fn the_body_limit_applies_to_streaming_h2_responses() {
    let upstream = Server::bind_with_config(
        "127.0.0.1:0",
        ServerConfig {
            http2: true,
            threads: 1,
            ..Default::default()
        },
    )
    .unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let handle = upstream
        .serve_background(|_req: Request<Body>| {
            let (tx, body) = courierust::courierust_body::channel();
            std::thread::spawn(move || {
                let chunk = courierust::courierust_bytes::Bytes::from(vec![b'x'; 768]);
                let _ = tx.send(chunk.clone());
                let _ = tx.send(chunk);
            });
            let mut resp = Response::<Body>::with_status(200.into());
            resp.body = body;
            resp
        })
        .unwrap();
    std::mem::forget(handle);
    let upstream = format!("http://{upstream_addr}");
    let proxy_client = Client::with_config(ClientConfig {
        http2: true,
        max_body: 4 * 1024,
        ..Default::default()
    });
    let proxy = spawn_proxy(move |_| {
        ReverseProxy::new(proxy_client)
            .body_limit(1024)
            .route(prefix_route("/"), Url::parse(&upstream).unwrap())
    });

    let resp = Client::new().get(&format!("{proxy}/stream")).unwrap();
    assert_eq!(
        resp.status.as_u16(),
        502,
        "a streamed upstream body must not bypass the route limit"
    );
}

#[test]
fn route_body_limit_rejects_h1_response_before_reading_its_body() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (closed_tx, closed_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
        let mut request_head = Vec::new();
        let mut byte = [0u8; 1];
        while !request_head.ends_with(b"\r\n\r\n") {
            match stream.read(&mut byte) {
                Ok(0) | Err(_) => return,
                Ok(_) => request_head.push(byte[0]),
            }
        }
        if stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2097152\r\n\r\n")
            .is_err()
        {
            let _ = closed_tx.send(false);
            return;
        }
        let disconnected = match stream.read(&mut byte) {
            Ok(0) => true,
            Err(error) => matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::NotConnected
            ),
            Ok(_) => false,
        };
        let _ = closed_tx.send(disconnected);
    });

    let upstream = format!("http://{addr}");
    let proxy_client = Client::with_config(ClientConfig {
        max_body: 4 * 1024 * 1024,
        read_timeout: Some(Duration::from_secs(5)),
        ..Default::default()
    });
    let proxy = spawn_proxy(move |_| {
        ReverseProxy::new(proxy_client)
            .body_limit(1024)
            .route(prefix_route("/"), Url::parse(&upstream).unwrap())
    });

    let response = Client::new().get(&format!("{proxy}/large")).unwrap();
    assert_eq!(response.status.as_u16(), 502);
    assert!(
        closed_rx.recv_timeout(Duration::from_secs(1)).unwrap(),
        "the proxy must close an oversized upstream response without waiting for its body"
    );
}
