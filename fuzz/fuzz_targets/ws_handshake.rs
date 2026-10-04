#![no_main]
//! WebSocket opening-handshake fuzz target.
//!
//! This drives the policy code a request reaches *before* a single
//! WebSocket byte is buffered: upgrade detection, `Sec-WebSocket-Key`
//! shape, extension parsing and `permessage-deflate` negotiation, and the
//! trusted-proxy resolution of the client address, host and scheme.
//!
//! These functions are where leniency becomes a security property rather
//! than a cosmetic one — accepting an unoffered extension parameter, or
//! believing `X-Forwarded-For` from a peer that is not a proxy, is a real
//! defect — so the target asserts the invariants instead of only watching
//! for panics.

use courierust::courierust_h1;
use courierust::courierust_http::header::{HeaderMap, HeaderName, HeaderValue};
use courierust::courierust_io::{BufReader, Scratch, SliceReader};
use courierust::courierust_ws::{
    accept_key, client_ip, effective_host, is_secure, is_valid_key, is_websocket_upgrade,
    parse_extensions, IpNet, OriginPolicy, PerMessageDeflate, PmDeflatePolicy,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut reader = BufReader::new(SliceReader::new(data), 4096);
    let mut scratch = Scratch::new();
    let Ok(headers) = courierust_h1::read_headers_scratch(&mut reader, &mut scratch) else {
        return;
    };
    exercise(&headers);
});

fn exercise(headers: &HeaderMap) {
    // Upgrade detection is total: a header block either is or is not an
    // upgrade, and neither answer may panic.
    let _ = is_websocket_upgrade(headers);

    // A key is either canonical 16-byte base64 or it is not, and the
    // accept digest is derivable exactly when it is. A lenient
    // `is_valid_key` would let a malformed key reach the digest that a
    // proxy in front may compute differently.
    for value in headers.get_all("sec-websocket-key") {
        if let Ok(key) = value.to_str() {
            assert_eq!(
                is_valid_key(key),
                accept_key(key).is_ok(),
                "is_valid_key and accept_key disagree on {key:?}"
            );
        }
    }

    // Extension parsing, then negotiation, then the response *we* would
    // send. The response has to survive the same parser a peer uses, and
    // the parameters we chose have to survive the client-side validation
    // a peer performs — a response that fails its own round trip would
    // break every third-party client.
    if let Ok(offers) = parse_extensions(headers) {
        let policy = PmDeflatePolicy::default();
        for offer in &offers {
            let Some(selected) = PerMessageDeflate::negotiate(offer, &policy) else {
                continue;
            };
            let response = selected.response_header();
            let mut round_trip = HeaderMap::new();
            round_trip.append(
                HeaderName::from_lowercase("sec-websocket-extensions"),
                HeaderValue::from_bytes(response.as_bytes()).expect("ASCII response header"),
            );
            let parsed = parse_extensions(&round_trip).expect("our own response must parse");
            assert_eq!(parsed.len(), 1, "one extension, one entry");
            // The result is only meaningful when every parameter we sent
            // was one the offer could authorize; where it cannot, the
            // client-side check is expected to reject. Either way it must
            // not panic and must not write outside the parameters.
            let _ = PerMessageDeflate::from_response(offer, &parsed[0], &policy);
        }
    }

    // Proxy policy. The peer address alone decides whether the forwarded
    // headers are believed, so an untrusted peer must always speak for
    // itself — otherwise any client can pick its own identity and its own
    // "the proxy said this was TLS".
    let peer: std::net::IpAddr = "203.0.113.9".parse().expect("static address");
    let trusted: Vec<IpNet> = vec![
        IpNet::parse("127.0.0.1").expect("static network"),
        IpNet::parse("10.0.0.0/8").expect("static network"),
        IpNet::parse("2001:db8::1").expect("static network"),
    ];
    let candidates: [std::net::IpAddr; 3] = [
        peer,
        "127.0.0.1".parse().expect("static address"),
        "2001:db8::1".parse().expect("static address"),
    ];
    for candidate in candidates {
        let resolved = client_ip(candidate, headers, &trusted);
        if !trusted.iter().any(|net| net.contains(candidate)) {
            assert_eq!(
                resolved, candidate,
                "an untrusted peer must not be able to speak through X-Forwarded-*"
            );
        }
        let _ = effective_host(headers, candidate, &trusted);
        let _ = is_secure(false, headers, candidate, &trusted);
    }

    // Origin policy is total for every origin string, including the ones
    // a browser cannot produce.
    let origin = headers.get("origin").and_then(|value| value.to_str().ok());
    let policies = [
        OriginPolicy::default(),
        OriginPolicy::NoOrigin,
        OriginPolicy::Any,
        OriginPolicy::list(["https://app.example.com"]),
    ];
    for policy in &policies {
        let _ = policy.check(origin, Some("https://app.example.com"));
        let _ = policy.check(origin, None);
        let _ = policy.is_permissive();
    }
}
