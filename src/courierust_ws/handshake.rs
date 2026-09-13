//! WebSocket opening handshake (RFC 6455 §4) and the security policy
//! that surrounds it.
//!
//! Three things live here, in order of how often they get *wrong* in the
//! wild:
//!
//! 1. **Origin policy.** Browsers do not apply the same-origin policy to
//!    WebSocket connects, so the Origin header is the *only* anti-CSRF
//!    defence a WebSocket endpoint has. Behind a TLS-terminating reverse
//!    proxy (Nginx, Traefik, …) the request arrives on a plain socket,
//!    so the scheme/host a policy must compare against come from the
//!    `X-Forwarded-*` headers — which are attacker-controllable unless
//!    the *peer address* is a known proxy. [`OriginPolicy`] therefore
//!    takes the peer address into account through [`IpNet`], and only
//!    honours forwarded headers from addresses inside the configured
//!    trusted set.
//! 2. **Handshake validation.** `Sec-WebSocket-Key` shape,
//!    `Sec-WebSocket-Version` (exactly 13, and exactly once),
//!    duplicate-header rejection, token-level `Connection`/`Upgrade`
//!    parsing. Any of these being sloppy is a request-smuggling or
//!    cache-poisoning hazard when a proxy sits in front.
//! 3. **Extension negotiation**, specifically `permessage-deflate`
//!    (RFC 7692) with strict parameter validation on both sides — the
//!    client must verify the server only picked parameters it offered.

use crate::courierust_crypto::{base64, sha1::Sha1};
use crate::courierust_error::{Error, Result};
use crate::courierust_http::header::HeaderMap;
use crate::courierust_http::method::Method;
use crate::courierust_http::request::Request;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::net::IpAddr;

/// The RFC 6455 §4.2.2 handshake GUID.
pub const WS_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// The only protocol version this implementation speaks.
pub const WS_VERSION: u16 = 13;

/// `Sec-WebSocket-Accept` for a client key: base64(SHA-1(key || GUID)).
///
/// The `key` must already be shape-validated ([`is_valid_key`]); a bad
/// key is a protocol error rather than a silently different digest.
pub fn accept_key(key: &str) -> Result<String> {
    if !is_valid_key(key) {
        return Err(Error::protocol("websocket: malformed Sec-WebSocket-Key"));
    }
    let mut digest = Sha1::new();
    digest.update(key.as_bytes());
    digest.update(WS_GUID);
    Ok(base64::encode(&digest.finish()))
}

/// Encode 16 bytes of entropy as a `Sec-WebSocket-Key`.
///
/// Split out from [`generate_key`] so the `no_std` core stays free of
/// platform entropy sources and tests can pin the value.
pub fn key_from_entropy(entropy: &[u8; 16]) -> String {
    base64::encode(entropy)
}

/// A fresh `Sec-WebSocket-Key` from the platform CSPRNG.
#[cfg(feature = "std")]
pub fn generate_key() -> Result<String> {
    let mut entropy = [0u8; 16];
    if !crate::courierust_tls::crypto::rng::fill_random(&mut entropy) {
        return Err(Error::io(
            "websocket: the platform entropy source is unavailable",
        ));
    }
    Ok(key_from_entropy(&entropy))
}

/// Whether `key` is a canonical base64 encoding of exactly 16 bytes.
///
/// Shape matters: a proxy in front may normalize a longer/shorter key
/// differently from this server, and the accept digest is computed over
/// the *decoded* nonce. Requiring the exact 24-character form removes
/// the ambiguity that a lenient check would introduce.
///
/// The check is allocation-free (`decoded_size` validates and measures
/// in one pass), because it runs on every handshake.
pub fn is_valid_key(key: &str) -> bool {
    key.len() == 24 && key.ends_with("==") && matches!(base64::decoded_size(key.as_bytes()), Ok(16))
}

/// Case-insensitive token search in a comma-separated header value
/// (RFC 9110 §5.6.1: `Connection: keep-alive, Upgrade`).
pub fn header_has_token(headers: &HeaderMap, name: &str, token: &str) -> bool {
    headers.get_all(name).any(|v| {
        let Ok(s) = v.to_str() else { return false };
        s.split(',').any(|t| t.trim().eq_ignore_ascii_case(token))
    })
}

/// `Connection: Upgrade` + `Upgrade: websocket` + exactly one
/// `Sec-WebSocket-Key` + exactly one `Sec-WebSocket-Version`.
pub fn is_websocket_upgrade(headers: &HeaderMap) -> bool {
    if headers.get_all("sec-websocket-key").count() != 1 {
        return false;
    }
    if headers.get_all("sec-websocket-version").count() != 1 {
        return false;
    }
    let upgrade_ok = header_has_token(headers, "upgrade", "websocket");
    upgrade_ok && header_has_token(headers, "connection", "upgrade")
}

// ---------------------------------------------------------------------
// Trusted proxies
// ---------------------------------------------------------------------

/// An IP address plus prefix length (`10.0.0.0/8`, `2001:db8::/32`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpNet {
    /// Network address.
    pub addr: IpAddr,
    /// Prefix length in bits.
    pub prefix: u8,
}

impl IpNet {
    /// Parse `addr`, `addr/len` or a bare address (host route).
    pub fn parse(s: &str) -> Option<Self> {
        let (addr, prefix) = match s.split_once('/') {
            Some((a, p)) => (a.trim(), Some(p.trim().parse::<u8>().ok()?)),
            None => (s.trim(), None),
        };
        let addr: IpAddr = addr.parse().ok()?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        // A bare address is a host route, so its prefix length follows the
        // address family. Defaulting it to /32 would turn `::1` into a
        // network that also contains every `::x`, including the IPv4-
        // mapped addresses a dual-stack listener reports — and a trusted
        // proxy match is what makes the forwarded headers believed.
        let prefix = prefix.unwrap_or(max);
        if prefix > max {
            return None;
        }
        Some(Self { addr, prefix })
    }

    /// A single-host network.
    pub fn host(addr: IpAddr) -> Self {
        Self {
            addr,
            prefix: if addr.is_ipv4() { 32 } else { 128 },
        }
    }

    /// Whether `ip` falls inside the network.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let bits = self.prefix.min(32);
                if bits == 0 {
                    return true;
                }
                let mask = u32::MAX << (32 - bits);
                (u32::from(net) & mask) == (u32::from(ip) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let bits = self.prefix.min(128);
                if bits == 0 {
                    return true;
                }
                let mask: u128 = u128::MAX << (128 - bits);
                (u128::from(net) & mask) == (u128::from(ip) & mask)
            }
            _ => false,
        }
    }
}

/// Whether `ip` is covered by any entry of `nets`.
pub fn is_trusted_proxy(ip: IpAddr, nets: &[IpNet]) -> bool {
    nets.iter().any(|n| n.contains(ip))
}

/// The effective client address.
///
/// With a trusted peer, `X-Forwarded-For` is resolved with the
/// “right-most address that is not itself a trusted proxy” rule: taking
/// the *left-most* value lets any client prepend a forged address, and
/// taking the whole chain lets a header grow without bound.
pub fn client_ip(peer: IpAddr, headers: &HeaderMap, trusted: &[IpNet]) -> IpAddr {
    if !is_trusted_proxy(peer, trusted) {
        return peer;
    }
    if let Some(v) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        for part in v.split(',').rev() {
            let token = part.trim();
            if token.is_empty() {
                continue;
            }
            let cleaned = token
                .trim_start_matches('[')
                .split_once(']')
                .map(|(host, _)| host)
                .unwrap_or(token);
            let cleaned = if cleaned.contains(':') && cleaned.matches(':').count() == 1 {
                cleaned.split(':').next().unwrap_or(cleaned)
            } else {
                cleaned
            };
            if let Ok(ip) = cleaned.parse::<IpAddr>() {
                if !is_trusted_proxy(ip, trusted) {
                    return ip;
                }
            }
        }
    }
    if let Some(v) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
        if let Ok(ip) = v.trim().parse::<IpAddr>() {
            return ip;
        }
    }
    peer
}

/// The `Host` the client actually addressed.
///
/// `X-Forwarded-Host` (and Traefik's `X-Forwarded-Server` fallback) is
/// only honoured when the peer is a trusted proxy — otherwise any client
/// could rewrite the host a same-origin check compares against.
pub fn effective_host(headers: &HeaderMap, peer: IpAddr, trusted: &[IpNet]) -> Option<String> {
    if is_trusted_proxy(peer, trusted) {
        for name in ["x-forwarded-host", "x-forwarded-server"] {
            if let Some(v) = headers.get(name).and_then(|v| v.to_str().ok()) {
                let first = v.split(',').next().unwrap_or("").trim();
                if !first.is_empty() {
                    return Some(first.to_ascii_lowercase());
                }
            }
        }
    }
    headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_ascii_lowercase())
}

/// Whether the *client* spoke TLS — directly, or through a trusted proxy
/// that terminated it (`X-Forwarded-Proto: https`).
pub fn is_secure(tls_active: bool, headers: &HeaderMap, peer: IpAddr, trusted: &[IpNet]) -> bool {
    if tls_active {
        return true;
    }
    if !is_trusted_proxy(peer, trusted) {
        return false;
    }
    if let Some(v) = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
    {
        let first = v.split(',').next().unwrap_or("").trim();
        return first.eq_ignore_ascii_case("https") || first.eq_ignore_ascii_case("wss");
    }
    false
}

// ---------------------------------------------------------------------
// Origin policy
// ---------------------------------------------------------------------

/// What `Origin` values a server accepts.
///
/// The default is [`OriginPolicy::SameOrigin`]: the `Origin` header must
/// name the origin the request was addressed to. That is the only
/// default that cannot be exploited by a random web page, and it still
/// accepts non-browser clients that send no `Origin` at all.
#[derive(Debug, Clone, Default)]
pub enum OriginPolicy {
    /// Accept every request, including cross-origin ones.
    ///
    /// Only appropriate for endpoints that are safe to call from any
    /// page (public read-only feeds) *and* are protected against CSRF
    /// by another mechanism (a token in the URL).
    Any,
    /// Accept only requests without an `Origin` header (non-browser
    /// clients such as native apps, and same-process tests). A browser
    /// request is always rejected.
    NoOrigin,
    /// Accept an explicit allow-list; `https://*.example.com` matches any
    /// subdomain of `example.com` (`*.example.com` never matches the apex
    /// host).
    List(Vec<String>),
    /// Accept only the origin the client addressed (host from `Host` /
    /// trusted `X-Forwarded-Host`, scheme from TLS / trusted
    /// `X-Forwarded-Proto`), and accept a missing `Origin`.
    #[default]
    SameOrigin,
}

impl OriginPolicy {
    /// Build a list policy from string literals.
    pub fn list<I, S>(origins: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self::List(origins.into_iter().map(Into::into).collect())
    }

    /// Whether `origin` is acceptable for a request addressed to
    /// `request_origin` (`scheme://host[:port]`).
    pub fn check(&self, origin: Option<&str>, request_origin: Option<&str>) -> bool {
        match self {
            Self::Any => true,
            Self::NoOrigin => origin.is_none(),
            Self::List(allowed) => match origin {
                None => false,
                Some(o) => allowed.iter().any(|a| origin_matches(a, o)),
            },
            Self::SameOrigin => match (origin, request_origin) {
                (None, _) => true,
                (Some(o), Some(r)) => origin_equivalent(o, r),
                (Some(_), None) => false,
            },
        }
    }

    /// `true` when this policy performs a real check (used for startup
    /// warnings and for the `same_origin` default’s documentation).
    pub fn is_permissive(&self) -> bool {
        matches!(self, Self::Any)
    }
}

/// `scheme://host[:port]` normalisation for comparison: scheme and host
/// are case-insensitive, default ports are implicit, IPv6 literals keep
/// their brackets out of the comparison.
///
/// A malformed origin (unknown scheme, empty host, non-numeric port, a
/// colon that is not a port separator) returns `None`, and every
/// comparison involving `None` is `false`: an origin that cannot be
/// normalised must never accidentally match an allow-list entry.
fn split_origin(o: &str) -> Option<(String, String, u16)> {
    let (scheme, rest) = o.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    let default_port = match scheme.as_str() {
        "https" | "wss" => 443u16,
        "http" | "ws" => 80u16,
        _ => return None,
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    if authority.is_empty() {
        return None;
    }

    let last_colon = authority.rfind(':');
    let last_bracket = authority.rfind(']');
    let (host, port) = match last_colon {
        Some(c) if last_bracket.map_or(true, |b| c > b) => {
            let port = authority[c + 1..].parse::<u16>().ok()?;
            (&authority[..c], port)
        }
        _ => (authority, default_port),
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() {
        return None;
    }
    let port = match (port, scheme.as_str()) {
        (443, "https" | "wss") | (80, "http" | "ws") => default_port,
        (p, _) => p,
    };
    Some((scheme, host.to_ascii_lowercase(), port))
}

/// Whether the origin string `origin` matches the allow-list entry
/// `rule` (which may use a `*.` host prefix).
pub fn origin_matches(rule: &str, origin: &str) -> bool {
    let Some((rule_scheme, rule_host, rule_port)) = split_origin(rule) else {
        return false;
    };
    let Some((o_scheme, o_host, o_port)) = split_origin(origin) else {
        return false;
    };
    if rule_scheme != o_scheme || rule_port != o_port {
        return false;
    }
    if let Some(suffix) = rule_host.strip_prefix("*.") {
        return o_host.len() > suffix.len()
            && o_host.ends_with(suffix)
            && o_host.as_bytes()[o_host.len() - suffix.len() - 1] == b'.';
    }
    rule_host == o_host
}

/// Whether two origin strings denote the same origin.
pub fn origin_equivalent(a: &str, b: &str) -> bool {
    match (split_origin(a), split_origin(b)) {
        (Some(x), Some(y)) => x == y,
        _ => false,
    }
}

// ---------------------------------------------------------------------
// Extensions (RFC 6455 §9.1 / RFC 7692)
// ---------------------------------------------------------------------

/// One offered or selected extension with its parameters.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExtensionOffer {
    /// Extension token, lowercased.
    pub name: String,
    /// Parameters in wire order: `("server_max_window_bits", Some("12"))`.
    pub params: Vec<(String, Option<String>)>,
}

impl ExtensionOffer {
    /// Value of a parameter, if present.
    pub fn param(&self, name: &str) -> Option<Option<&str>> {
        self.params
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_deref())
    }

    /// Whether a (value-less) parameter is present.
    pub fn has_param(&self, name: &str) -> bool {
        self.param(name).is_some()
    }
}

/// Parse every `Sec-WebSocket-Extensions` header field.
///
/// Quoted strings and comma/semicolon separation follow RFC 9110 §5.6.1;
/// a syntactically invalid list is an error rather than “unknown
/// extension, skip it”, because a proxy and this endpoint have to agree
/// on what was offered before anything is selected.
pub fn parse_extensions(headers: &HeaderMap) -> Result<Vec<ExtensionOffer>> {
    let mut out = Vec::new();
    for value in headers.get_all("sec-websocket-extensions") {
        let text = value
            .to_str()
            .map_err(|_| Error::protocol("websocket: non-ASCII Sec-WebSocket-Extensions"))?;
        out.extend(parse_extension_value(text)?);
    }
    Ok(out)
}

/// Parse one `Sec-WebSocket-Extensions` field value.
///
/// The same parser reads a peer's header and the client's own offer, so a
/// client can validate the response against the *exact* string it sent
/// instead of a second, hand-written copy of its offer.
pub fn parse_extension_value(text: &str) -> Result<Vec<ExtensionOffer>> {
    let mut out = Vec::new();
    for entry in split_quoted(text, ',')? {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let mut parts = split_quoted(entry, ';')?;
        let name = parts.remove(0).trim().to_ascii_lowercase();
        if !is_token(&name) {
            return Err(Error::protocol("websocket: invalid extension token"));
        }
        let mut params = Vec::new();
        for p in parts {
            let p = p.trim();
            if p.is_empty() {
                continue;
            }
            let (k, v) = match p.split_once('=') {
                Some((k, v)) => {
                    let v = v.trim();
                    let v = if v.len() >= 2 && v.starts_with('"') && v.ends_with('"') {
                        &v[1..v.len() - 1]
                    } else {
                        v
                    };
                    if !is_token(v) {
                        return Err(Error::protocol(
                            "websocket: invalid extension parameter value",
                        ));
                    }
                    (k.trim().to_ascii_lowercase(), Some(String::from(v)))
                }
                None => (p.to_ascii_lowercase(), None),
            };
            if !is_token(&k) {
                return Err(Error::protocol("websocket: invalid extension parameter"));
            }
            if params
                .iter()
                .any(|(n, _): &(String, Option<String>)| *n == k)
            {
                return Err(Error::protocol("websocket: duplicate extension parameter"));
            }
            params.push((k, v));
        }
        out.push(ExtensionOffer { name, params });
    }
    Ok(out)
}

/// Split on `sep` while honouring double-quoted segments.
fn split_quoted(s: &str, sep: char) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut escaped = false;
    for c in s.chars() {
        if escaped {
            cur.push(c);
            escaped = false;
            continue;
        }
        match c {
            '\\' if in_quotes => {
                cur.push(c);
                escaped = true;
            }
            '"' => {
                in_quotes = !in_quotes;
                cur.push(c);
            }
            c if c == sep && !in_quotes => {
                out.push(core::mem::take(&mut cur));
            }
            c => cur.push(c),
        }
    }
    if in_quotes {
        return Err(Error::protocol("websocket: unterminated quoted string"));
    }
    out.push(cur);
    Ok(out)
}

/// RFC 9110 token.
fn is_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

/// `permessage-deflate` parameters after negotiation (RFC 7692 §7.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PerMessageDeflate {
    /// The server will not retain the compression context between
    /// messages.
    pub server_no_context_takeover: bool,
    /// The client must not retain the compression context.
    pub client_no_context_takeover: bool,
    /// Window bits the server may use for its compressor.
    pub server_max_window_bits: u8,
    /// Window bits the client may use for its compressor.
    pub client_max_window_bits: u8,
}

impl Default for PerMessageDeflate {
    fn default() -> Self {
        Self {
            server_no_context_takeover: false,
            client_no_context_takeover: false,
            server_max_window_bits: 15,
            client_max_window_bits: 15,
        }
    }
}

/// Server-side policy for `permessage-deflate`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PmDeflatePolicy {
    /// Offer/accept compression at all.
    pub enabled: bool,
    /// Largest window the server's compressor may use (8..=15).
    pub max_server_window_bits: u8,
    /// Largest window the server will let the client's compressor use.
    pub max_client_window_bits: u8,
    /// Whether the server wants `no_context_takeover` on both directions
    /// (lower memory, slightly worse ratio).
    pub prefer_no_context_takeover: bool,
}

impl Default for PmDeflatePolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            max_server_window_bits: 15,
            max_client_window_bits: 15,
            prefer_no_context_takeover: false,
        }
    }
}

fn parse_window_bits(value: Option<&str>, name: &str) -> Result<u8> {
    let v = value
        .ok_or_else(|| Error::protocol(alloc::format!("websocket: {name} requires a value")))?;
    let bits: u8 = v
        .parse()
        .map_err(|_| Error::protocol(alloc::format!("websocket: invalid {name}")))?;
    if !(8..=15).contains(&bits) {
        return Err(Error::protocol(alloc::format!(
            "websocket: {name} must be 8..=15"
        )));
    }
    Ok(bits)
}

impl PerMessageDeflate {
    /// Select parameters for the server role from one client offer.
    ///
    /// Returns `None` when the offer cannot be satisfied by the policy
    /// (in which case the extension is simply not selected, which is
    /// legal — the connection proceeds uncompressed).
    pub fn negotiate(offer: &ExtensionOffer, policy: &PmDeflatePolicy) -> Option<Self> {
        if !policy.enabled || offer.name != "permessage-deflate" {
            return None;
        }
        let mut selected = Self::default();

        // Parameters the client must not send a value for.
        if offer.params.iter().any(|(n, v)| {
            matches!(
                n.as_str(),
                "server_no_context_takeover" | "client_no_context_takeover"
            ) && v.is_some()
        }) {
            return None;
        }

        if let Some(v) = offer.param("server_max_window_bits") {
            let bits = parse_window_bits(v, "server_max_window_bits").ok()?;
            selected.server_max_window_bits = bits.min(policy.max_server_window_bits);
        } else {
            selected.server_max_window_bits = policy.max_server_window_bits;
        }
        if let Some(v) = offer.param("client_max_window_bits") {
            selected.client_max_window_bits = match v {
                Some(text) => parse_window_bits(Some(text), "client_max_window_bits").ok()?,
                None => policy.max_client_window_bits,
            };
            selected.client_max_window_bits = selected
                .client_max_window_bits
                .min(policy.max_client_window_bits);
        } else {
            // Without the parameter the client's window is fixed at 15.
            selected.client_max_window_bits = 15;
        }
        selected.server_no_context_takeover =
            offer.has_param("server_no_context_takeover") || policy.prefer_no_context_takeover;
        selected.client_no_context_takeover =
            offer.has_param("client_no_context_takeover") || policy.prefer_no_context_takeover;
        Some(selected)
    }

    /// The `Sec-WebSocket-Extensions` value that announces this choice.
    pub fn response_header(&self) -> String {
        let mut s = String::from("permessage-deflate");
        if self.server_no_context_takeover {
            s.push_str("; server_no_context_takeover");
        }
        if self.client_no_context_takeover {
            s.push_str("; client_no_context_takeover");
        }
        if self.server_max_window_bits != 15 {
            s.push_str("; server_max_window_bits=");
            s.push_str(&self.server_max_window_bits.to_string());
        }
        if self.client_max_window_bits != 15 {
            s.push_str("; client_max_window_bits=");
            s.push_str(&self.client_max_window_bits.to_string());
        }
        s
    }

    /// Validate a server's response against what the client offered.
    ///
    /// RFC 7692 §7.1.2: the server may only use parameters the client
    /// offered, must not introduce a parameter that changes the client's
    /// send direction unless it was offered, and must not respond with
    /// `server_max_window_bits` larger than offered. A client that skips
    /// these checks can be steered into an unbounded window.
    pub fn from_response(
        offer: &ExtensionOffer,
        response: &ExtensionOffer,
        client_policy: &PmDeflatePolicy,
    ) -> Result<Self> {
        if response.name != "permessage-deflate" {
            return Err(Error::protocol(
                "websocket: unexpected extension in response",
            ));
        }
        if offer.name != "permessage-deflate" {
            return Err(Error::protocol(
                "websocket: server selected an extension that was not offered",
            ));
        }
        let mut out = Self::default();
        for (name, value) in &response.params {
            match name.as_str() {
                "server_no_context_takeover" => {
                    if value.is_some() {
                        return Err(Error::protocol("websocket: parameter takes no value"));
                    }
                    out.server_no_context_takeover = true;
                }
                "client_no_context_takeover" => {
                    if value.is_some() {
                        return Err(Error::protocol("websocket: parameter takes no value"));
                    }
                    out.client_no_context_takeover = true;
                }
                "server_max_window_bits" => {
                    let bits = parse_window_bits(value.as_deref(), "server_max_window_bits")?;
                    // RFC 7692 §7.1.2.1: a server MAY include this parameter
                    // even when the offer did not carry it, so an unoffered
                    // value is accepted — it is still capped at 15 by
                    // `parse_window_bits`, so it cannot widen our window.
                    // Only a value *larger than offered* is a failure.
                    if let Some(Some(offered)) = offer.param("server_max_window_bits") {
                        let offered: u8 = offered
                            .parse()
                            .map_err(|_| Error::protocol("websocket: bad offer"))?;
                        if bits > offered {
                            return Err(Error::protocol(
                                "websocket: server window larger than offered",
                            ));
                        }
                    }
                    out.server_max_window_bits = bits;
                }
                "client_max_window_bits" => {
                    if !offer.has_param("client_max_window_bits") {
                        return Err(Error::protocol(
                            "websocket: client_max_window_bits was not offered",
                        ));
                    }
                    let bits = parse_window_bits(value.as_deref(), "client_max_window_bits")?;
                    let offered = match offer.param("client_max_window_bits") {
                        Some(Some(text)) => text.parse::<u8>().map_err(|_| {
                            Error::protocol("websocket: malformed client_max_window_bits offer")
                        })?,
                        _ => 15,
                    };
                    let cap = client_policy.max_client_window_bits.min(15).min(offered);
                    out.client_max_window_bits = bits.min(cap);
                }
                _ => {
                    return Err(Error::protocol(
                        "websocket: unknown permessage-deflate parameter",
                    ))
                }
            }
        }
        Ok(out)
    }

    /// Map to the *server* endpoint's send/receive view.
    pub fn server_view(&self) -> CompressionParams {
        CompressionParams {
            send_window_bits: self.server_max_window_bits,
            send_no_context_takeover: self.server_no_context_takeover,
            recv_window_bits: self.client_max_window_bits,
            recv_no_context_takeover: self.client_no_context_takeover,
        }
    }

    /// Map to the *client* endpoint's send/receive view.
    pub fn client_view(&self) -> CompressionParams {
        CompressionParams {
            send_window_bits: self.client_max_window_bits,
            send_no_context_takeover: self.client_no_context_takeover,
            recv_window_bits: self.server_max_window_bits,
            recv_no_context_takeover: self.server_no_context_takeover,
        }
    }
}

/// Role-independent compression settings handed to a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CompressionParams {
    /// Window bits of *our* compressor.
    pub send_window_bits: u8,
    /// We must not retain compression state across messages.
    pub send_no_context_takeover: bool,
    /// Window bits the peer's compressor promised.
    pub recv_window_bits: u8,
    /// The peer must not retain compression state across messages.
    pub recv_no_context_takeover: bool,
}

// ---------------------------------------------------------------------
// The parsed opening handshake
// ---------------------------------------------------------------------

/// Everything a service needs to decide about an upgrade request.
#[derive(Debug, Clone)]
pub struct WsOffer {
    /// Request target (path + query).
    pub path: String,
    /// `Host`/`X-Forwarded-Host` as seen by the policy.
    pub host: Option<String>,
    /// `Origin`, verbatim.
    pub origin: Option<String>,
    /// `Sec-WebSocket-Key`, verbatim.
    pub key: String,
    /// `Sec-WebSocket-Protocol` values in client preference order.
    pub protocols: Vec<String>,
    /// `Sec-WebSocket-Extensions` offers in wire order.
    pub extensions: Vec<ExtensionOffer>,
    /// Remote address of the transport peer.
    pub peer: IpAddr,
    /// Client address after trusted-proxy resolution.
    pub client_ip: IpAddr,
    /// Whether the client's connection was encrypted (directly or at a
    /// trusted proxy).
    pub secure: bool,
}

impl Default for WsOffer {
    /// An empty offer from an unspecified peer: `IpAddr` has no
    /// `Default`, and “unspecified” is the honest value for an offer
    /// that was not parsed from a request.
    fn default() -> Self {
        Self {
            path: String::new(),
            host: None,
            origin: None,
            key: String::new(),
            protocols: Vec::new(),
            extensions: Vec::new(),
            peer: IpAddr::V4(core::net::Ipv4Addr::UNSPECIFIED),
            client_ip: IpAddr::V4(core::net::Ipv4Addr::UNSPECIFIED),
            secure: false,
        }
    }
}

impl WsOffer {
    /// The `scheme://host[:port]` this request was addressed to.
    pub fn request_origin(&self) -> Option<String> {
        let host = self.host.as_ref()?;
        let scheme = if self.secure { "https" } else { "http" };
        Some(alloc::format!("{scheme}://{host}"))
    }

    /// Parse and validate an upgrade request.
    ///
    /// `tls_active` is the transport state (not a header), so a client
    /// cannot claim to be on TLS.
    pub fn parse<B>(
        req: &Request<B>,
        peer: IpAddr,
        tls_active: bool,
        trusted_proxies: &[IpNet],
    ) -> Result<Self> {
        if req.method != Method::GET {
            return Err(Error::protocol("websocket: upgrade requires GET"));
        }
        if !is_websocket_upgrade(&req.headers) {
            return Err(Error::protocol("websocket: not an upgrade request"));
        }
        let key = req
            .headers
            .get("sec-websocket-key")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !is_valid_key(key) {
            return Err(Error::protocol("websocket: malformed Sec-WebSocket-Key"));
        }
        let version = req
            .headers
            .get("sec-websocket-version")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let version: u16 = version
            .trim()
            .parse()
            .map_err(|_| Error::protocol("websocket: missing Sec-WebSocket-Version"))?;
        if version != WS_VERSION {
            return Err(Error::with_message(
                crate::courierust_error::ErrorKind::Protocol,
                "websocket: unsupported Sec-WebSocket-Version",
            ));
        }
        let mut protocols = Vec::new();
        for v in req.headers.get_all("sec-websocket-protocol") {
            let text = v
                .to_str()
                .map_err(|_| Error::protocol("websocket: non-ASCII subprotocol list"))?;
            for p in text.split(',') {
                let p = p.trim();
                if p.is_empty() {
                    continue;
                }
                if !is_token(p) {
                    return Err(Error::protocol("websocket: invalid subprotocol token"));
                }
                if protocols.iter().any(|q: &String| q == p) {
                    return Err(Error::protocol(
                        "websocket: duplicate subprotocol in request",
                    ));
                }
                protocols.push(String::from(p));
            }
        }
        let extensions = parse_extensions(&req.headers)?;
        let client = client_ip(peer, &req.headers, trusted_proxies);
        Ok(Self {
            path: String::from(req.uri.as_str()),
            host: effective_host(&req.headers, peer, trusted_proxies),
            origin: req
                .headers
                .get("origin")
                .and_then(|v| v.to_str().ok())
                .map(String::from),
            key: String::from(key),
            protocols,
            extensions,
            peer,
            client_ip: client,
            secure: is_secure(tls_active, &req.headers, peer, trusted_proxies),
        })
    }

    /// Select the subprotocol: the first server-preference entry that the
    /// client also offered (RFC 6455 leaves the choice to the server; a
    /// server-preference order keeps the outcome stable when a client
    /// sends several).
    pub fn select_protocol(&self, supported: &[String]) -> Option<String> {
        supported
            .iter()
            .find(|s| self.protocols.iter().any(|c| c == *s))
            .cloned()
    }

    /// Find an offered extension by name.
    pub fn extension(&self, name: &str) -> Option<&ExtensionOffer> {
        self.extensions.iter().find(|e| e.name == name)
    }
}

/// The `401`/`403`-style reason an upgrade was refused (kept as data so
/// callers can log a precise cause without string matching).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeRejection {
    /// Not a GET request.
    Method,
    /// Missing/invalid `Upgrade`/`Connection` tokens.
    NotUpgrade,
    /// `Sec-WebSocket-Key` missing, duplicated or malformed.
    BadKey,
    /// Version missing or not 13.
    UnsupportedVersion,
    /// `Origin` rejected by policy.
    Origin,
    /// Subprotocol list malformed or no overlap with the server's list.
    Subprotocol,
    /// Extension list malformed or unsatisfiable.
    Extensions,
}

impl HandshakeRejection {
    /// HTTP status to answer with.
    pub fn status(self) -> u16 {
        match self {
            Self::Method => 405,
            Self::NotUpgrade => 400,
            Self::BadKey => 400,
            Self::UnsupportedVersion => 426,
            Self::Origin => 403,
            Self::Subprotocol => 400,
            Self::Extensions => 400,
        }
    }

    /// Short, stable description for logs.
    pub fn reason(self) -> &'static str {
        match self {
            Self::Method => "upgrade requires GET",
            Self::NotUpgrade => "not a websocket upgrade",
            Self::BadKey => "bad Sec-WebSocket-Key",
            Self::UnsupportedVersion => "unsupported Sec-WebSocket-Version",
            Self::Origin => "origin rejected",
            Self::Subprotocol => "no acceptable subprotocol",
            Self::Extensions => "unsatisfiable extensions",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::courierust_http::header::{HeaderName, HeaderValue};

    fn req_with(headers: &[(&str, &str)]) -> Request<()> {
        let mut req = Request::new(Method::GET, "/chat");
        for (n, v) in headers {
            req.headers.append(
                HeaderName::from_bytes(n.as_bytes()).unwrap(),
                HeaderValue::from_bytes(v.as_bytes()).unwrap(),
            );
        }
        req
    }

    fn upgrade_headers() -> Vec<(&'static str, &'static str)> {
        alloc::vec![
            ("host", "example.com"),
            ("upgrade", "websocket"),
            ("connection", "keep-alive, Upgrade"),
            ("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ=="),
            ("sec-websocket-version", "13"),
        ]
    }

    #[test]
    fn rfc6455_accept_vector() {
        assert_eq!(
            accept_key("dGhlIHNhbXBsZSBub25jZQ==").unwrap(),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn key_shape_is_strict() {
        assert!(is_valid_key("dGhlIHNhbXBsZSBub25jZQ=="));
        assert!(!is_valid_key("dGhlIHNhbXBsZSBub25jZQ=")); // 23 chars
        assert!(!is_valid_key("dGhlIHNhbXBsZSBub25jZQ")); // no padding
        assert!(!is_valid_key("dGhlIHNhbXBsZSBub25jZQ==X"));
        assert!(!is_valid_key("!!!!!!!!!!!!!!!!!!!!===="));
        assert!(accept_key("short").is_err());
    }

    #[test]
    fn upgrade_detection_needs_every_piece() {
        let req = req_with(&upgrade_headers());
        assert!(is_websocket_upgrade(&req.headers));

        let missing_conn = req_with(&[
            ("upgrade", "websocket"),
            ("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ=="),
            ("sec-websocket-version", "13"),
        ]);
        assert!(!is_websocket_upgrade(&missing_conn.headers));

        // `Connection: closex` must not be read as the `upgrade` token.
        let bogus = req_with(&[
            ("upgrade", "websocket"),
            ("connection", "closex"),
            ("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ=="),
            ("sec-websocket-version", "13"),
        ]);
        assert!(!is_websocket_upgrade(&bogus.headers));

        // Duplicate key headers are a smuggling hazard.
        let dup = req_with(&[
            ("upgrade", "websocket"),
            ("connection", "Upgrade"),
            ("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ=="),
            ("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ=="),
            ("sec-websocket-version", "13"),
        ]);
        assert!(!is_websocket_upgrade(&dup.headers));
    }

    #[test]
    fn parses_a_full_offer() {
        let mut headers = upgrade_headers();
        headers.push(("origin", "https://app.example.com"));
        headers.push(("sec-websocket-protocol", "chat.v2, chat.v1"));
        headers.push((
            "sec-websocket-extensions",
            "permessage-deflate; client_max_window_bits=12, superzip",
        ));
        let req = req_with(&headers);
        let offer = WsOffer::parse(&req, "127.0.0.1".parse().unwrap(), false, &[]).unwrap();
        assert_eq!(offer.path, "/chat");
        assert_eq!(offer.host.as_deref(), Some("example.com"));
        assert_eq!(offer.origin.as_deref(), Some("https://app.example.com"));
        assert_eq!(offer.protocols, alloc::vec!["chat.v2", "chat.v1"]);
        assert_eq!(offer.extensions.len(), 2);
        assert_eq!(
            offer
                .extension("permessage-deflate")
                .unwrap()
                .param("client_max_window_bits"),
            Some(Some("12"))
        );
        assert_eq!(
            offer.select_protocol(&["chat.v1".to_string()]),
            Some("chat.v1".to_string())
        );
        assert_eq!(
            offer.request_origin().as_deref(),
            Some("http://example.com")
        );
    }

    #[test]
    fn rejects_bad_version_and_method() {
        let mut headers = upgrade_headers();
        headers[4] = ("sec-websocket-version", "8");
        let req = req_with(&headers);
        assert!(WsOffer::parse(&req, "127.0.0.1".parse().unwrap(), false, &[]).is_err());

        let mut req = req_with(&upgrade_headers());
        req.method = Method::POST;
        assert!(WsOffer::parse(&req, "127.0.0.1".parse().unwrap(), false, &[]).is_err());
    }

    /// Origin normalisation is the thing an allow-list stands on, so its
    /// edges are pinned: default ports fold away, IPv6 literals keep
    /// their brackets out of the comparison, and anything that cannot be
    /// normalised refuses to match anything at all.
    #[test]
    fn origin_normalisation_edges() {
        // Default ports are implicit.
        assert!(origin_equivalent("https://a.com", "https://a.com:443"));
        assert!(origin_equivalent("http://a.com", "http://a.com:80"));
        // A non-default port is part of the origin.
        assert!(!origin_equivalent("https://a.com", "https://a.com:8443"));
        // Case-insensitive scheme and host, case-sensitive path ignored.
        assert!(origin_equivalent("HTTPS://A.COM", "https://a.com"));
        assert!(origin_matches("https://a.com", "https://a.com/any/path"));

        // IPv6 literals: the brackets come off, and the port is only the
        // colon *after* the closing bracket.
        assert!(origin_equivalent(
            "https://[::1]:8443",
            "https://[::1]:8443"
        ));
        assert!(!origin_equivalent("https://[::1]", "https://[::1]:8443"));
        assert!(origin_equivalent("https://[::1]", "https://[::1]:443"));
        assert!(origin_matches(
            "https://[2001:db8::1]:8443",
            "https://[2001:db8::1]:8443"
        ));
        assert!(!origin_matches(
            "https://[2001:db8::1]:8443",
            "https://[2001:db8::2]:8443"
        ));

        // Malformed origins never match: no scheme, empty host, a bad
        // port, or an unknown scheme.
        for bad in [
            "example.com",
            "https://",
            "https://:443",
            "https://a.com:notaport",
            "ftp://a.com",
            "",
        ] {
            assert!(!origin_matches("https://a.com", bad), "{bad}");
            assert!(!origin_equivalent(bad, bad), "{bad}");
            assert!(!origin_matches(bad, "https://a.com"), "{bad}");
        }
    }

    #[test]
    fn origin_policy_matrix() {
        let p = OriginPolicy::SameOrigin;
        assert!(p.check(None, None));
        assert!(p.check(
            Some("https://ws.example.com"),
            Some("https://ws.example.com")
        ));
        assert!(!p.check(
            Some("https://ws.example.com"),
            Some("https://other.example.com")
        ));
        assert!(!p.check(Some("https://evil.test"), None));

        // Explicit list, with subdomain wildcards.
        let p = OriginPolicy::List(alloc::vec!["https://app.example.com".to_string()]);
        assert!(p.check(Some("https://app.example.com"), None));
        assert!(p.check(Some("HTTPS://APP.EXAMPLE.COM"), None));
        assert!(p.check(Some("https://app.example.com:443"), None));
        assert!(!p.check(Some("https://app.example.com:8443"), None));
        assert!(!p.check(Some("http://app.example.com"), None));
        assert!(!p.check(Some("https://app.example.com.evil.test"), None));
        assert!(!p.check(None, None));

        let p = OriginPolicy::List(alloc::vec!["https://*.example.com".to_string()]);
        assert!(p.check(Some("https://a.example.com"), None));
        assert!(p.check(Some("https://a.b.example.com"), None));
        assert!(!p.check(Some("https://example.com"), None));
        assert!(!p.check(Some("https://evil-example.com"), None));

        // NoOrigin: only native clients pass.
        let p = OriginPolicy::NoOrigin;
        assert!(p.check(None, None));
        assert!(!p.check(
            Some("https://ws.example.com"),
            Some("https://ws.example.com")
        ));

        // Any: everything passes (opt-in only).
        assert!(OriginPolicy::Any.check(Some("https://evil.test"), None));
    }

    #[test]
    fn forwarded_headers_are_only_trusted_from_proxies() {
        let headers = {
            let mut h = HeaderMap::new();
            h.insert(
                HeaderName::from_lowercase("x-forwarded-for"),
                HeaderValue::from_static("203.0.113.9, 10.0.0.5"),
            );
            h.insert(
                HeaderName::from_lowercase("x-forwarded-proto"),
                HeaderValue::from_static("https"),
            );
            h.insert(
                HeaderName::from_lowercase("x-forwarded-host"),
                HeaderValue::from_static("ws.example.com"),
            );
            h
        };
        let attacker: IpAddr = "203.0.113.9".parse().unwrap();
        assert_eq!(client_ip(attacker, &headers, &[]), attacker);
        assert!(!is_secure(false, &headers, attacker, &[]));
        assert_eq!(effective_host(&headers, attacker, &[]), None);

        let trusted = [IpNet::parse("10.0.0.0/8").unwrap()];
        let proxy: IpAddr = "10.0.0.5".parse().unwrap();
        assert_eq!(client_ip(proxy, &headers, &trusted), attacker);
        assert!(is_secure(false, &headers, proxy, &trusted));
        assert_eq!(
            effective_host(&headers, proxy, &trusted).as_deref(),
            Some("ws.example.com")
        );
    }

    #[test]
    fn ipnet_matching() {
        let n = IpNet::parse("10.0.0.0/8").unwrap();
        assert!(n.contains("10.1.2.3".parse().unwrap()));
        assert!(!n.contains("11.1.2.3".parse().unwrap()));
        let v6 = IpNet::parse("2001:db8::/32").unwrap();
        assert!(v6.contains("2001:db8:1234::1".parse().unwrap()));
        assert!(!v6.contains("2001:db9::1".parse().unwrap()));
        // A bare address is a host route.
        let host = IpNet::parse("127.0.0.1").unwrap();
        assert!(host.contains("127.0.0.1".parse().unwrap()));
        assert!(!host.contains("127.0.0.2".parse().unwrap()));
        assert!(IpNet::parse("10.0.0.0/33").is_none());
        assert!(IpNet::parse("not-an-ip").is_none());
        // A bare IPv6 address is a host route too: defaulting it to /32
        // (the IPv4 width) would make `::1` match `::2` and every
        // IPv4-mapped address, and a trusted-proxy match is what makes the
        // X-Forwarded-* headers believed.
        assert_eq!(IpNet::parse("::1").unwrap().prefix, 128);
        assert_eq!(IpNet::host("::1".parse().unwrap()).prefix, 128);
        let v6_host = IpNet::parse("::1").unwrap();
        assert!(v6_host.contains("::1".parse().unwrap()));
        assert!(!v6_host.contains("::2".parse().unwrap()));
        assert!(!v6_host.contains("::ffff:10.0.0.1".parse().unwrap()));
        assert!(!IpNet::host("::1".parse().unwrap()).contains("2001:db8::1".parse().unwrap()));
        // v4 and v6 never mix.
        assert!(!IpNet::parse("0.0.0.0/0")
            .unwrap()
            .contains("::1".parse().unwrap()));
    }

    #[test]
    fn extension_parsing_and_negotiation() {
        let mut headers = HeaderMap::new();
        headers.append(
            HeaderName::from_lowercase("sec-websocket-extensions"),
            HeaderValue::from_static(
                "permessage-deflate; server_no_context_takeover; client_max_window_bits=10, permessage-deflate; client_max_window_bits",
            ),
        );
        let offers = parse_extensions(&headers).unwrap();
        assert_eq!(offers.len(), 2);

        let policy = PmDeflatePolicy::default();
        let selected = PerMessageDeflate::negotiate(&offers[0], &policy).unwrap();
        assert!(selected.server_no_context_takeover);
        assert!(!selected.client_no_context_takeover);
        assert_eq!(selected.client_max_window_bits, 10);
        let header = selected.response_header();
        assert!(header.contains("server_no_context_takeover"));
        assert!(header.contains("client_max_window_bits=10"));

        // A valueless client_max_window_bits lets the server choose.
        let selected = PerMessageDeflate::negotiate(&offers[1], &policy).unwrap();
        assert_eq!(selected.client_max_window_bits, 15);
        // ...and the choice is announced with a value.
        assert!(!selected
            .response_header()
            .contains("client_max_window_bits=15"));

        // Policy can refuse compression entirely.
        let off = PmDeflatePolicy {
            enabled: false,
            ..Default::default()
        };
        assert!(PerMessageDeflate::negotiate(&offers[0], &off).is_none());
    }

    #[test]
    fn response_validation_rejects_unoffered_parameters() {
        let mut headers = HeaderMap::new();
        headers.append(
            HeaderName::from_lowercase("sec-websocket-extensions"),
            HeaderValue::from_static("permessage-deflate"),
        );
        let offer = parse_extensions(&headers).unwrap().remove(0);
        let policy = PmDeflatePolicy::default();

        // RFC 7692 §7.1.2.1: a server MAY answer with
        // server_max_window_bits even though the offer did not carry it,
        // and refusing that rejects an otherwise compliant server.
        let mut ok = HeaderMap::new();
        ok.append(
            HeaderName::from_lowercase("sec-websocket-extensions"),
            HeaderValue::from_static("permessage-deflate; server_max_window_bits=10"),
        );
        let resp = parse_extensions(&ok).unwrap().remove(0);
        let selected = PerMessageDeflate::from_response(&offer, &resp, &policy).unwrap();
        assert_eq!(selected.server_max_window_bits, 10);
        assert_eq!(selected.client_max_window_bits, 15);

        // ...but a value *larger than offered* is a failure (§7.1.2.1).
        let mut offered = HeaderMap::new();
        offered.append(
            HeaderName::from_lowercase("sec-websocket-extensions"),
            HeaderValue::from_static("permessage-deflate; server_max_window_bits=8"),
        );
        let offer_8 = parse_extensions(&offered).unwrap().remove(0);
        assert!(PerMessageDeflate::from_response(&offer_8, &resp, &policy).is_err());

        // client_max_window_bits is the other way round (§7.1.2.2): the
        // server may only pick it when the client offered it.
        let mut bad = HeaderMap::new();
        bad.append(
            HeaderName::from_lowercase("sec-websocket-extensions"),
            HeaderValue::from_static("permessage-deflate; client_max_window_bits=10"),
        );
        let resp = parse_extensions(&bad).unwrap().remove(0);
        assert!(PerMessageDeflate::from_response(&offer, &resp, &policy).is_err());

        let mut bad = HeaderMap::new();
        bad.append(
            HeaderName::from_lowercase("sec-websocket-extensions"),
            HeaderValue::from_static("permessage-deflate; nonsense"),
        );
        let resp = parse_extensions(&bad).unwrap().remove(0);
        assert!(PerMessageDeflate::from_response(&offer, &resp, &policy).is_err());

        // The plain echo is fine.
        let resp = offer.clone();
        assert!(PerMessageDeflate::from_response(&offer, &resp, &policy).is_ok());
    }

    #[test]
    fn window_bits_bounds_are_enforced() {
        let mut headers = HeaderMap::new();
        headers.append(
            HeaderName::from_lowercase("sec-websocket-extensions"),
            HeaderValue::from_static("permessage-deflate; client_max_window_bits=7"),
        );
        let offers = parse_extensions(&headers).unwrap();
        assert!(PerMessageDeflate::negotiate(&offers[0], &PmDeflatePolicy::default()).is_none());

        let mut headers = HeaderMap::new();
        headers.append(
            HeaderName::from_lowercase("sec-websocket-extensions"),
            HeaderValue::from_static("permessage-deflate; server_no_context_takeover=1"),
        );
        let offers = parse_extensions(&headers).unwrap();
        assert!(PerMessageDeflate::negotiate(&offers[0], &PmDeflatePolicy::default()).is_none());
    }

    #[test]
    fn malformed_extension_lists_are_errors() {
        let mut headers = HeaderMap::new();
        headers.append(
            HeaderName::from_lowercase("sec-websocket-extensions"),
            HeaderValue::from_static("permessage-deflate; client_max_window_bits=\"12"),
        );
        assert!(parse_extensions(&headers).is_err());

        let mut headers = HeaderMap::new();
        headers.append(
            HeaderName::from_lowercase("sec-websocket-extensions"),
            HeaderValue::from_static("permessage-deflate; x=1; x=2"),
        );
        assert!(parse_extensions(&headers).is_err());

        let mut headers = HeaderMap::new();
        headers.append(
            HeaderName::from_lowercase("sec-websocket-extensions"),
            HeaderValue::from_static("bad name; y"),
        );
        assert!(parse_extensions(&headers).is_err());
    }

    #[test]
    fn compression_views_are_role_relative() {
        let pm = PerMessageDeflate {
            server_no_context_takeover: true,
            client_no_context_takeover: false,
            server_max_window_bits: 12,
            client_max_window_bits: 10,
        };
        let s = pm.server_view();
        assert_eq!(s.send_window_bits, 12);
        assert_eq!(s.recv_window_bits, 10);
        assert!(s.send_no_context_takeover);
        let c = pm.client_view();
        assert_eq!(c.send_window_bits, 10);
        assert_eq!(c.recv_window_bits, 12);
    }

    #[test]
    fn entropy_to_key_roundtrip() {
        let entropy = [0u8; 16];
        let key = key_from_entropy(&entropy);
        assert!(is_valid_key(&key));
        assert_eq!(key, "AAAAAAAAAAAAAAAAAAAAAA==");
    }
}
