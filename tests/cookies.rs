//! The cookie jar as the client actually uses it: storing what a server
//! sets, and sending it back only where it belongs.

mod common;

use courierust::courierust_body::Body;
use courierust::courierust_client::cookies::CookieJar;
use courierust::courierust_client::{Client, ClientConfig};
use courierust::courierust_http::header::{HeaderName, HeaderValue};
use courierust::courierust_http::method::Method;
use courierust::courierust_http::request::Request;
use courierust::courierust_http::response::Response;
use courierust::courierust_server::{Server, ServerConfig};
use std::sync::{Arc, Mutex};

/// Every request the server saw, as `(path, cookie header)`.
type Seen = Arc<Mutex<Vec<(String, Option<String>)>>>;

/// A server that sets, clears and redirects on fixed paths.
fn spawn(seen: Seen) -> String {
    let server = Server::bind_with_config("127.0.0.1:0", ServerConfig::default()).unwrap();
    let addr = server.local_addr().unwrap();
    let handle = server
        .serve_background(move |req: Request<Body>| {
            let path = req.uri.as_str().to_string();
            let cookie = req
                .headers
                .get("cookie")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            seen.lock().unwrap().push((path.clone(), cookie));
            let mut resp = Response::<Body>::with_status(200.into());
            let set = |resp: &mut Response<Body>, value: &'static str| {
                resp.headers.insert(
                    HeaderName::from_lowercase("set-cookie"),
                    HeaderValue::from_static(value),
                );
            };
            match path.as_str() {
                "/set" => set(&mut resp, "sid=1; Path=/"),
                "/clear" => set(&mut resp, "sid=1; Path=/; Max-Age=0"),
                "/go" => {
                    resp.status = 302.into();
                    resp.headers.insert(
                        HeaderName::from_lowercase("location"),
                        HeaderValue::from_static("/end"),
                    );
                }
                _ => {}
            }
            resp
        })
        .unwrap();
    std::mem::forget(handle);
    format!("http://{addr}")
}

fn jar_client(jar: Arc<Mutex<CookieJar>>) -> Client {
    Client::with_config(ClientConfig {
        cookie_jar: Some(jar),
        ..Default::default()
    })
}

#[test]
fn nothing_is_stored_unless_a_jar_is_installed() {
    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    let base = spawn(seen.clone());
    let client = Client::new();
    client.get(&format!("{base}/set")).unwrap();
    client.get(&format!("{base}/end")).unwrap();
    let seen = seen.lock().unwrap();
    assert_eq!(seen[0].1, None);
    assert_eq!(
        seen[1].1, None,
        "a client with no jar must stay stateless, however loudly the server asks"
    );
}

#[test]
fn a_set_cookie_comes_back_on_the_next_request() {
    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    let base = spawn(seen.clone());
    let jar = Arc::new(Mutex::new(CookieJar::new()));
    let client = jar_client(jar.clone());

    client.get(&format!("{base}/set")).unwrap();
    assert_eq!(jar.lock().unwrap().len(), 1, "the cookie was stored");
    client.get(&format!("{base}/end")).unwrap();

    let seen = seen.lock().unwrap();
    assert_eq!(
        seen[0].1, None,
        "nothing was stored yet on the first request"
    );
    assert_eq!(seen[1].1.as_deref(), Some("sid=1"));
}

#[test]
fn a_jar_cookie_is_resent_after_a_redirect() {
    // The follow-up is rebuilt from the caller's own head, not from the head
    // the previous hop carried — so the jar has to be consulted again, and
    // the cookie must not be lost because the redirect code rewrote the
    // headers.
    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    let base = spawn(seen.clone());
    let jar = Arc::new(Mutex::new(CookieJar::new()));
    let client = jar_client(jar.clone());

    client.get(&format!("{base}/set")).unwrap();
    client.get(&format!("{base}/go")).unwrap();

    let seen = seen.lock().unwrap();
    assert_eq!(seen[1].0, "/go");
    assert_eq!(seen[1].1.as_deref(), Some("sid=1"));
    assert_eq!(seen[2].0, "/end", "the redirect was followed");
    assert_eq!(
        seen[2].1.as_deref(),
        Some("sid=1"),
        "the jar applies to the follow-up too"
    );
}

#[test]
fn a_caller_supplied_cookie_header_wins() {
    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    let base = spawn(seen.clone());
    let jar = Arc::new(Mutex::new(CookieJar::new()));
    let client = jar_client(jar.clone());
    client.get(&format!("{base}/set")).unwrap();

    let mut req = Request::<Body>::new(Method::GET, "/end");
    req.headers.insert(
        HeaderName::from_lowercase("cookie"),
        HeaderValue::from_static("mine=1"),
    );
    client.execute(&format!("{base}/end"), req).unwrap();

    let seen = seen.lock().unwrap();
    assert_eq!(
        seen[1].1.as_deref(),
        Some("mine=1"),
        "a caller that speaks for itself is not second-guessed"
    );
}

#[test]
fn a_deletion_removes_the_cookie() {
    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    let base = spawn(seen.clone());
    let jar = Arc::new(Mutex::new(CookieJar::new()));
    let client = jar_client(jar.clone());

    client.get(&format!("{base}/set")).unwrap();
    client.get(&format!("{base}/clear")).unwrap();
    client.get(&format!("{base}/end")).unwrap();

    assert!(jar.lock().unwrap().is_empty());
    let seen = seen.lock().unwrap();
    assert_eq!(seen[1].1.as_deref(), Some("sid=1"));
    assert_eq!(
        seen[2].1, None,
        "a `Max-Age=0` must actually end the session"
    );
}

#[test]
fn a_cloned_client_shares_the_session() {
    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    let base = spawn(seen.clone());
    let jar = Arc::new(Mutex::new(CookieJar::new()));
    let client = jar_client(jar);
    let clone = client.clone();

    client.get(&format!("{base}/set")).unwrap();
    clone.get(&format!("{base}/end")).unwrap();

    let seen = seen.lock().unwrap();
    assert_eq!(
        seen[1].1.as_deref(),
        Some("sid=1"),
        "one client, one session, however many clones"
    );
}
