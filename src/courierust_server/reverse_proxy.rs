//! A reverse proxy: it accepts requests from clients and forwards them to
//! an upstream server.
//!
//! It is a [`Handler`], so it installs on a
//! [`Server`](crate::courierust_server::Server) like any other handler, and
//! it keeps one pooled [`Client`] for the upstream — the point of a reverse
//! proxy is that it does not open a connection per request.
//!
//! What it does, in the terms RFC 9110 uses:
//!
//! * **Routing** — longest matching path prefix wins, and a route may match
//!   on `Host` instead. The matched prefix is *replaced* by the upstream's
//!   own path, so `http://up:8081/base` + a request for `/api/x` on the
//!   `/api` route becomes `/base/x` upstream.
//! * **Load balancing** — a route owns a *set* of equivalent upstreams and
//!   picks one per request, by [`Balance::RoundRobin`] or
//!   [`Balance::LeastConnections`].
//! * **Outlier ejection** — an upstream that fails [`HealthPolicy::failures`]
//!   times in a row leaves the rotation for [`HealthPolicy::cooldown`], so a
//!   dead backend costs a handful of requests instead of its share of every
//!   request for as long as it stays dead. Only *transport* failures count:
//!   an upstream that answers `500` is alive, and ejecting it would turn its
//!   bug into an outage of the whole route.
//! * **WebSocket upgrades** — on a route that opts in with
//!   [`Route::upgrade`], the upgrade is forwarded: the proxy dials the
//!   upstream as a WebSocket client and carries messages both ways.
//! * **In-flight limits** — [`Upstream::max_in_flight`] bounds how many
//!   requests one backend may have open at once. A route that has nothing
//!   left to hand a request to answers `503` rather than queueing it: a
//!   queue needs a size and a timeout, and both of those are a latency
//!   budget nobody chose.
//! * **Hop-by-hop headers** — never forwarded, in either direction
//!   (RFC 9110 §7.6.1). Forwarding `Connection`/`Transfer-Encoding` is how a
//!   proxy desynchronises the two connections it sits between.
//! * **`Via`**, **`X-Forwarded-For`**, **`X-Forwarded-Proto`** and
//!   **`X-Forwarded-Host`** — added. `X-Forwarded-For` is *appended* to the
//!   chain that arrived, because a chain of proxies is the normal case and
//!   overwriting it destroys the only record of where the request came
//!   from — but only when the peer is one this proxy was told to trust
//!   ([`ReverseProxy::trust`]). The header is client-writable, so relaying an
//!   untrusted peer's copy would let any client choose the address the next
//!   hop logs, rate-limits or authorises against; from a peer that is not
//!   trusted, the inbound chain is dropped and replaced with the address this
//!   proxy actually saw.
//!
//! What it deliberately does **not** do:
//!
//! * **No replay.** A request that failed on one upstream is not sent to
//!   another. The failure may have happened after the upstream received it,
//!   and a proxy that silently duplicates a `POST` is a proxy that charges a
//!   card twice. Ejection is the recovery mechanism instead: the bad
//!   upstream stops being chosen, and whether to retry is the client's call.
//! * **No `Upgrade` other than WebSocket.** The server never hands a handler
//!   the raw connection, so an h2c (or any other) upgrade cannot be relayed;
//!   a request carrying one is answered `501` rather than forwarded as
//!   something it is not. Silent degradation here looks like a broken client
//!   for no visible reason.
//! * **No header rewriting beyond the list above** (no `Location` rewrite on
//!   redirects, no cookie-domain rewriting). A caller that needs them can
//!   wrap the handler and post-process the response.
//!
//! The WebSocket path is a *message* relay, not a frame relay: both
//! handshakes and both codecs are terminated here, so a message may be
//! reframed on its way through, and the two legs negotiate their extensions
//! independently — a client that offered `permessage-deflate` keeps it
//! whether or not the upstream also agreed to it. It costs one thread per
//! proxied socket, because the server's reactor polls the client's socket
//! while the upstream leg is blocking.

use crate::courierust_body::Body;
use crate::courierust_bytes::Bytes;
use crate::courierust_client::ws::{WebSocket, WsClientOptions, WsClientWriter};
use crate::courierust_client::Client;
use crate::courierust_error::Error;
use crate::courierust_h1::is_hop_by_hop;
use crate::courierust_http::header::{HeaderMap, HeaderName, HeaderValue};
use crate::courierust_http::request::Request;
use crate::courierust_http::response::Response;
use crate::courierust_http::status::StatusCode;
use crate::courierust_http::uri::Url;
use crate::courierust_server::ws::{WsConn, WsData, WsSender, WsService, WsUpgradeReply};
use crate::courierust_server::{ConnectionInfo, Handler};
use crate::courierust_ws::{is_trusted_proxy, Event, IpNet};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// How a route decides it owns a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Matcher {
    /// A path prefix. `/api` matches `/api`, `/api/` and `/api/v1/x` but not
    /// `/apifoo` — a prefix is a path segment boundary, not a byte prefix.
    Prefix(String),
    /// An exact `Host` header value (`host:port` as sent).
    Host(String),
}

/// How a route spreads requests over its upstreams.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Balance {
    /// Each request goes to the next upstream in turn.
    ///
    /// The default: it needs nothing but a cursor, and for upstreams that
    /// are interchangeable — the only case in which balancing is meaningful
    /// at all — it is the policy whose fairness does not depend on how long
    /// a response takes.
    #[default]
    RoundRobin,
    /// Each request goes to the upstream with the fewest requests in flight
    /// at the moment it is handed out.
    ///
    /// Better when responses differ widely in cost: round robin can stack
    /// ten slow requests on one upstream while its neighbour sits idle.
    /// Ties fall to the upstream nearest the cursor, so a route whose
    /// upstreams are all idle still rotates instead of pinning the first.
    LeastConnections,
}

/// When an upstream is taken out of rotation.
///
/// The counting is passive — no health-check traffic — because a proxy that
/// probes its upstreams has to be right about the probe interval, the
/// timeout and the meaning of a `503` from an application that is merely
/// busy. Counting real requests the proxy was going to send anyway has no
/// such parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HealthPolicy {
    /// Consecutive transport failures that eject an upstream.
    ///
    /// `0` disables ejection.
    pub failures: u32,
    /// How long an ejected upstream stays out before it is tried again.
    pub cooldown: Duration,
}

impl Default for HealthPolicy {
    fn default() -> Self {
        Self {
            failures: 3,
            cooldown: Duration::from_secs(10),
        }
    }
}

/// One backend.
#[derive(Debug, Clone)]
pub struct Upstream {
    /// The upstream's base URL, e.g. `http://127.0.0.1:8081` or
    /// `https://internal.example`. A path here becomes the prefix that
    /// replaces the matched route's own prefix; a query here is prepended to
    /// the request's own.
    ///
    /// The proxy always sends `Host` = this authority. The client derives
    /// `Host` from the URL it is given, and pretending otherwise would mean
    /// connecting to the client's host instead of the upstream's; a
    /// deployment that needs the original name keeps it in
    /// `X-Forwarded-Host`.
    pub base: Url,
    /// The most requests this upstream may have in flight at once.
    ///
    /// `0` means no limit. A limit is how one backend is protected from a
    /// route that would otherwise hand it everything it has: a recovering
    /// backend that can serve one request at a time is still useful, and a
    /// proxy that gives it fifty undoes the recovery it is waiting on. When
    /// every upstream of a route is at its limit, the request is answered
    /// `503` rather than queued.
    pub max_in_flight: usize,
}

impl From<Url> for Upstream {
    fn from(base: Url) -> Self {
        Self::new(base)
    }
}

impl Upstream {
    /// One backend at `base`, with no in-flight limit.
    pub fn new(base: Url) -> Self {
        Self {
            base,
            max_in_flight: 0,
        }
    }

    /// One backend admitting at most `max` requests at a time (`0` = no
    /// limit).
    pub fn limited(base: Url, max: usize) -> Self {
        Self {
            base,
            max_in_flight: max,
        }
    }
}

/// One route.
#[derive(Debug, Clone)]
pub struct Route {
    /// What the route matches.
    pub matcher: Matcher,
    /// The upstreams a match is spread over.
    ///
    /// They are interchangeable by definition — nothing else about the
    /// request changes when one is chosen instead of another. An empty list
    /// is a configuration error that shows up as a `503`, not as silence.
    pub upstreams: Vec<Upstream>,
    /// How those upstreams are chosen.
    pub balance: Balance,
    /// Whether this route forwards WebSocket upgrades.
    ///
    /// Off by default: forwarding an upgrade is a decision to hold two
    /// connections open for as long as the application keeps them, and a
    /// route that does it by accident is how a fleet of sockets appears on
    /// a backend nobody meant to expose.
    pub upgrade: bool,
}

impl Route {
    /// A route with one upstream.
    pub fn to(matcher: Matcher, base: impl Into<Upstream>) -> Self {
        Self {
            matcher,
            upstreams: alloc::vec![base.into()],
            balance: Balance::RoundRobin,
            upgrade: false,
        }
    }

    /// A route spread over `bases`.
    pub fn balanced<I, U>(matcher: Matcher, balance: Balance, bases: I) -> Self
    where
        I: IntoIterator<Item = U>,
        U: Into<Upstream>,
    {
        Self {
            matcher,
            upstreams: bases.into_iter().map(Into::into).collect(),
            balance,
            upgrade: false,
        }
    }

    /// Forward WebSocket upgrades on this route (off by default).
    pub fn upgrade(mut self, yes: bool) -> Self {
        self.upgrade = yes;
        self
    }
}

/// A route plus the mutable state that spreads requests over it.
///
/// The routing table is immutable once built; only this state changes, and
/// each route owns its own lock, so requests on different routes never wait
/// for each other.
struct RouteEntry {
    route: Route,
    rotation: Mutex<Rotation>,
}

#[derive(Debug, Default)]
struct Rotation {
    /// Where round robin is, and where ties in least-connections fall.
    cursor: usize,
    backends: Vec<Backend>,
}

#[derive(Debug, Default, Clone, Copy)]
struct Backend {
    in_flight: usize,
    /// Consecutive transport failures since the last success.
    failures: u32,
    /// When this upstream may be chosen again.
    ejected_until: Option<Instant>,
}

impl Backend {
    fn is_ejected(&self, now: Instant) -> bool {
        self.ejected_until.is_some_and(|until| until > now)
    }
}

/// The outcome of [`ReverseProxy::reserve`].
///
/// Three outcomes, because they mean three different things to an operator:
/// a misconfigured route, a saturated one, and a healthy one.
enum Pick<'a> {
    /// A reservation on one upstream, given back when the slot is dropped.
    Ready(Slot<'a>),
    /// The route has no upstreams at all.
    NoUpstream,
    /// Every upstream that could take a request is at its in-flight limit.
    AllBusy,
}

/// A reservation on one upstream.
///
/// In-flight counts are what [`Balance::LeastConnections`] reads and what
/// [`Upstream::max_in_flight`] enforces, so a count that is never given back
/// is not a leak — it is an outage: the upstream would come to look
/// permanently busy and the route would answer `503` for as long as it ran.
/// Keeping the reservation in a guard is what makes giving it back
/// unconditional, on every exit path including the ones a later edit adds.
struct Slot<'a> {
    proxy: &'a ReverseProxy,
    entry: &'a RouteEntry,
    index: usize,
    /// Set by [`Slot::finish`]. A slot that was never finished is discharged
    /// without being scored, because nothing proves the upstream was ever
    /// contacted.
    scored: bool,
}

impl Slot<'_> {
    /// The upstream this reservation is on.
    fn index(&self) -> usize {
        self.index
    }

    /// Give the reservation back and score the attempt.
    ///
    /// `reached` is "the upstream was contacted", not "the answer was
    /// `2xx`": a `404` from a live upstream must not count against it.
    fn finish(mut self, reached: bool) {
        self.scored = true;
        self.proxy
            .release(self.entry, self.index, reached, Instant::now());
    }
}

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        if !self.scored {
            self.proxy.discharge(self.entry, self.index);
        }
    }
}

/// The most requests `upstreams[index]` may have in flight, with `0` read as
/// "no limit" rather than "no traffic".
fn limit(upstreams: &[Upstream], index: usize) -> usize {
    match upstreams[index].max_in_flight {
        0 => usize::MAX,
        max => max,
    }
}

/// A reverse proxy.
pub struct ReverseProxy {
    routes: Vec<RouteEntry>,
    client: Client,
    /// The client cap before applying the proxy's route-level cap.
    client_max_body: usize,
    /// The `Via` pseudonym this proxy puts in its own entries.
    pseudonym: String,
    /// How many bytes this proxy will buffer in one direction: a request
    /// body before it hands it to the client, or an upstream response body
    /// before it hands it back. A larger one is answered `413` / `502`
    /// rather than read into memory.
    ///
    /// The upstream client's configured cap may impose a stricter response
    /// limit. `0` means "buffer nothing", not "unlimited".
    max_body: usize,
    health: HealthPolicy,
    /// Peers whose `X-Forwarded-For` is believed. See [`Self::trust`].
    trusted_peers: Vec<IpNet>,
}

impl ReverseProxy {
    /// A proxy that forwards through `client`.
    ///
    /// The client supplies the upstream transport policy (TLS, timeouts,
    /// pooling and any explicit forward proxy). The proxy deliberately does
    /// not inherit client-side stateful behaviour such as cookies, content
    /// decoding, retries or redirect following: an intermediary must relay
    /// one request and one response, not act as a second client on behalf of
    /// its caller.
    pub fn new(client: Client) -> Self {
        let client_max_body = client.config().max_body;
        Self {
            routes: Vec::new(),
            client,
            client_max_body,
            pseudonym: format!("courierust/{}", env!("CARGO_PKG_VERSION")),
            max_body: 16 * 1024 * 1024,
            health: HealthPolicy::default(),
            trusted_peers: Vec::new(),
        }
    }

    /// Add a route with one upstream.
    pub fn route(self, matcher: Matcher, upstream: impl Into<Upstream>) -> Self {
        self.route_all(matcher, [upstream])
    }

    /// Add a route spread over `upstreams`, by round robin.
    pub fn route_all<I, U>(self, matcher: Matcher, upstreams: I) -> Self
    where
        I: IntoIterator<Item = U>,
        U: Into<Upstream>,
    {
        self.balanced(matcher, Balance::RoundRobin, upstreams)
    }

    /// Add a route spread over `upstreams`, by `balance`.
    pub fn balanced<I, U>(self, matcher: Matcher, balance: Balance, upstreams: I) -> Self
    where
        I: IntoIterator<Item = U>,
        U: Into<Upstream>,
    {
        self.add_route(Route::balanced(matcher, balance, upstreams))
    }

    /// Add a route built by hand, for options the shortcuts do not cover.
    pub fn add_route(mut self, route: Route) -> Self {
        let backends = vec![Backend::default(); route.upstreams.len()];
        self.routes.push(RouteEntry {
            route,
            rotation: Mutex::new(Rotation {
                cursor: 0,
                backends,
            }),
        });
        self
    }

    /// How upstreams are taken out of rotation. See [`HealthPolicy`].
    pub fn health(mut self, policy: HealthPolicy) -> Self {
        self.health = policy;
        self
    }

    /// Peers whose `X-Forwarded-For` is believed, in the same spelling the
    /// server's own [`ServerConfig::websocket`](crate::courierust_server::ServerConfig)
    /// policy uses.
    ///
    /// Empty by default, and that default is the safe one: a proxy that has
    /// not been told who sits in front of it cannot tell a load balancer's
    /// chain from a client's forgery, so it treats the header as the latter
    /// and replaces it with the address it actually saw. A chain is only
    /// worth appending to when the entries already in it were written by
    /// something whose word this proxy has a reason to take.
    pub fn trust(mut self, peers: impl IntoIterator<Item = IpNet>) -> Self {
        self.trusted_peers = peers.into_iter().collect();
        self
    }

    /// The most bytes this proxy will buffer in one direction: a request body
    /// before it is forwarded (`413` if larger), or a buffered upstream
    /// response before it is handed back (`502` if larger).
    ///
    /// Defaults to 16 MiB, and `0` means "buffer nothing" rather than
    /// "unlimited". This also lowers the upstream client's protocol-level
    /// response limit so oversized bodies are rejected before buffering. If
    /// the client was configured with a smaller limit, that stricter cap is
    /// retained.
    pub fn body_limit(mut self, bytes: usize) -> Self {
        self.client = self.client.with_max_body(bytes.min(self.client_max_body));
        self.max_body = bytes;
        self
    }

    /// The configured routes.
    pub fn routes(&self) -> impl Iterator<Item = &Route> {
        self.routes.iter().map(|entry| &entry.route)
    }

    /// Override the `Via` pseudonym (the default names this crate).
    pub fn pseudonym(mut self, name: impl Into<String>) -> Self {
        self.pseudonym = name.into();
        self
    }

    /// The upstream leg's client.
    pub fn client(&self) -> &Client {
        &self.client
    }

    /// The route a request matches: the longest path prefix, or an exact
    /// host, whichever is more specific.
    fn entry_for(&self, req: &Request<Body>) -> Option<&RouteEntry> {
        let host = req
            .headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .map(|h| h.to_ascii_lowercase());
        let path = req.uri.path();
        self.routes
            .iter()
            .filter(|entry| match &entry.route.matcher {
                Matcher::Host(wanted) => host
                    .as_deref()
                    .is_some_and(|h| h.eq_ignore_ascii_case(wanted)),
                Matcher::Prefix(prefix) => prefix_match(path, prefix),
            })
            .max_by_key(|entry| match &entry.route.matcher {
                Matcher::Host(_) => usize::MAX,
                Matcher::Prefix(prefix) => prefix.len(),
            })
    }

    /// Reserve one upstream of `entry`, or report why none could be taken.
    ///
    /// The reservation's in-flight count is raised here and lowered in
    /// [`Self::release`] / [`Self::discharge`], so the lock is taken twice per
    /// request and never across the request itself: a slow upstream does not
    /// make the other requests on this route wait.
    fn reserve<'a>(&'a self, entry: &'a RouteEntry, now: Instant) -> Pick<'a> {
        let mut rotation = crate::lock(&entry.rotation);
        let upstreams = &entry.route.upstreams;
        if upstreams.is_empty() {
            return Pick::NoUpstream;
        }
        let has_room = |rotation: &Rotation, index: usize| {
            rotation.backends[index].in_flight < limit(upstreams, index)
        };
        let usable: Vec<usize> = (0..upstreams.len())
            .filter(|index| {
                !rotation.backends[*index].is_ejected(now) && has_room(&rotation, *index)
            })
            .collect();
        let chosen = if usable.is_empty() {
            if (0..upstreams.len()).any(|index| !rotation.backends[index].is_ejected(now)) {
                // Healthy but full. Not a reason to wait — there is no queue —
                // and not a failure, since these upstreams are working.
                return Pick::AllBusy;
            }
            // Everything is ejected. Waiting out the cooldown would turn a
            // recoverable upstream into an outage, so probe the one whose
            // ejection expires first — the longest-ejected one — provided it
            // has room.
            let mut best: Option<usize> = None;
            for index in 0..upstreams.len() {
                if !has_room(&rotation, index) {
                    continue;
                }
                let earlier = match best {
                    None => true,
                    Some(current) => {
                        rotation.backends[index].ejected_until
                            < rotation.backends[current].ejected_until
                    }
                };
                if earlier {
                    best = Some(index);
                }
            }
            match best {
                Some(index) => index,
                None => return Pick::AllBusy,
            }
        } else {
            match entry.route.balance {
                Balance::RoundRobin => usable[rotation.cursor % usable.len()],
                Balance::LeastConnections => {
                    let len = usable.len();
                    let start = rotation.cursor % len;
                    // Ties go to the upstream nearest the cursor, so a route
                    // whose upstreams are all idle still rotates.
                    let key = |index: usize| {
                        (
                            rotation.backends[index].in_flight,
                            (index + len - start) % len,
                        )
                    };
                    let mut best = usable[0];
                    for &candidate in usable.iter().skip(1) {
                        if key(candidate) < key(best) {
                            best = candidate;
                        }
                    }
                    best
                }
            }
        };
        rotation.cursor = rotation.cursor.wrapping_add(1);
        rotation.backends[chosen].in_flight += 1;
        Pick::Ready(Slot {
            proxy: self,
            entry,
            index: chosen,
            scored: false,
        })
    }

    /// Give back the slot taken by [`Self::acquire`], without scoring it.
    ///
    /// For the failures that are this proxy's own — a base URL that cannot
    /// produce a target, a body that is too large to buffer — the upstream
    /// was never contacted, and ejecting it for a local mistake would be
    /// ejecting the wrong thing.
    fn discharge(&self, entry: &RouteEntry, index: usize) {
        let mut rotation = crate::lock(&entry.rotation);
        if let Some(backend) = rotation.backends.get_mut(index) {
            backend.in_flight = backend.in_flight.saturating_sub(1);
        }
    }

    /// Give back the slot taken by [`Self::acquire`] and score the attempt.
    ///
    /// `reached` is "the upstream was contacted", not "the answer was
    /// `2xx`": a `404` from a live upstream must not count against it.
    fn release(&self, entry: &RouteEntry, index: usize, reached: bool, now: Instant) {
        let mut rotation = crate::lock(&entry.rotation);
        let Some(backend) = rotation.backends.get_mut(index) else {
            return;
        };
        backend.in_flight = backend.in_flight.saturating_sub(1);
        if reached {
            backend.failures = 0;
            backend.ejected_until = None;
            return;
        }
        if self.health.failures == 0 {
            return;
        }
        backend.failures = backend.failures.saturating_add(1);
        if backend.failures >= self.health.failures {
            backend.ejected_until = Some(now + self.health.cooldown);
            // Start counting again from the ejection: an upstream that comes
            // back healthy should not be one failure away from being thrown
            // out again.
            backend.failures = 0;
        }
    }

    /// Forward one request, returning what the upstream said — or a gateway
    /// error that names what went wrong.
    fn forward(&self, req: Request<Body>, info: Option<&ConnectionInfo>) -> Response<Body> {
        let Some(entry) = self.entry_for(&req) else {
            return self.error(StatusCode::NOT_FOUND, "no route matches this request");
        };
        if is_upgrade(&req.headers) {
            return self.error(
                StatusCode::NOT_IMPLEMENTED,
                "this route does not forward connection upgrades",
            );
        }
        let slot = match self.reserve(entry, Instant::now()) {
            Pick::Ready(slot) => slot,
            Pick::NoUpstream => {
                return self.error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "this route has no upstream",
                )
            }
            Pick::AllBusy => {
                return self.error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "every upstream of this route is at its in-flight limit",
                )
            }
        };
        let url = upstream_url(
            &entry.route,
            &entry.route.upstreams[slot.index()].base,
            &req,
        );
        let body = match collect_body(req.body, self.max_body) {
            Ok(body) => body,
            Err(error) => {
                // The slot is dropped un-finished: the upstream was never
                // contacted, so this must not count against it.
                return self.error(StatusCode::PAYLOAD_TOO_LARGE, &error.to_string());
            }
        };

        let mut headers = HeaderMap::with_capacity(req.headers.len() + 6);
        for (name, value) in req.headers.iter() {
            let literal = name.as_str();
            // `host` is the upstream's business: the client sets it from the
            // URL it is given. The rest are hop-by-hop (RFC 9110 §7.6.1) or
            // this proxy's own forwarding metadata, which is appended below
            // rather than relayed.
            if is_hop_by_hop_for(&req.headers, literal)
                || literal == "host"
                || matches!(
                    literal,
                    "via" | "x-forwarded-for" | "x-forwarded-proto" | "x-forwarded-host"
                )
            {
                continue;
            }
            headers.append(name.clone(), value.clone());
        }
        // `Via` is appended, never rewritten: the entries before ours are
        // the only record of the path the request took.
        let previous = req
            .headers
            .get("via")
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|v| !v.is_empty());
        let via = match previous {
            Some(previous) => format!("{previous}, 1.1 {}", self.pseudonym),
            None => format!("1.1 {}", self.pseudonym),
        };
        headers.insert(
            HeaderName::from_lowercase("via"),
            HeaderValue::from_bytes(via.as_bytes())
                .unwrap_or_else(|_| HeaderValue::from_static("1.1 courierust")),
        );
        if let Some(info) = info {
            // `X-Forwarded-For` is client-writable, so an inbound chain is
            // only worth preserving when the peer that sent it is one this
            // proxy was told to believe. Relaying it from anyone else would
            // let a client choose the address the next hop logs,
            // rate-limits or authorises against — and grow the header
            // without bound while doing it.
            let chain = if is_trusted_proxy(info.peer.ip(), &self.trusted_peers) {
                req.headers
                    .get("x-forwarded-for")
                    .and_then(|v| v.to_str().ok())
                    .map(str::trim)
                    .filter(|v| !v.is_empty())
            } else {
                None
            };
            let forwarded = match chain {
                Some(chain) => format!("{chain}, {}", info.peer.ip()),
                None => info.peer.ip().to_string(),
            };
            headers.insert(
                HeaderName::from_lowercase("x-forwarded-for"),
                HeaderValue::from_bytes(forwarded.as_bytes())
                    .unwrap_or_else(|_| HeaderValue::from_static("unknown")),
            );
            headers.insert(
                HeaderName::from_lowercase("x-forwarded-proto"),
                HeaderValue::from_static(if info.secure { "https" } else { "http" }),
            );
        }
        if let Some(host) = req.headers.get("host") {
            headers.insert(HeaderName::from_lowercase("x-forwarded-host"), host.clone());
        }

        let mut upstream_req = Request::<Body>::new(req.method.clone(), "/");
        upstream_req.headers = headers;
        // An empty body is `Empty`, not zero bytes of `Bytes`: the client
        // sends `Content-Length: 0` for the latter, and a GET that announces
        // a body it does not have is a request the peer is entitled to wait
        // on.
        upstream_req.body = if body.is_empty() {
            Body::Empty
        } else {
            Body::Bytes(Bytes::from(body))
        };
        let result = self.client.execute_unmanaged(&url, upstream_req);
        match result {
            Ok(resp) => {
                // Reading the response is still work the upstream is doing,
                // so this must remain inside the reservation. Otherwise a
                // long stream would be invisible to both the in-flight cap
                // and least-connections balancing as soon as its headers
                // arrived.
                let resp = self.to_client(resp);
                // `reached` decides ejection, and it is about the transport,
                // not the status: an upstream that answered `500` answered.
                slot.finish(true);
                resp
            }
            Err(error) => {
                slot.finish(false);
                self.error(StatusCode::BAD_GATEWAY, &error.to_string())
            }
        }
    }

    /// Sanitize an upstream response before it goes back to the client.
    fn to_client(&self, resp: Response<Body>) -> Response<Body> {
        // A channel-backed body has no length until it is read. Buffering it
        // here gives every upstream protocol the same hard limit and lets us
        // answer `502` before any successful response head reaches the
        // downstream client.
        let body = match resp.body.collect_limited(self.max_body) {
            Ok(body) => Body::from(body),
            Err(error) => {
                return self.error(
                    StatusCode::BAD_GATEWAY,
                    &format!(
                        "the upstream response exceeded this proxy's {}-byte limit or failed while streaming: {error}",
                        self.max_body
                    ),
                )
            }
        };
        let mut headers = HeaderMap::with_capacity(resp.headers.len() + 1);
        for (name, value) in resp.headers.iter() {
            if is_hop_by_hop_for(&resp.headers, name.as_str()) {
                continue;
            }
            headers.append(name.clone(), value.clone());
        }
        Response {
            status: resp.status,
            version: resp.version,
            headers,
            body,
            trailers: resp.trailers,
        }
    }

    fn error(&self, status: StatusCode, message: &str) -> Response<Body> {
        let mut resp = Response::<Body>::with_status(status);
        resp.headers.insert(
            HeaderName::from_lowercase("content-type"),
            HeaderValue::from_static("text/plain; charset=utf-8"),
        );
        resp.body = Body::Bytes(crate::courierust_bytes::Bytes::from(
            message.as_bytes().to_vec(),
        ));
        resp
    }
}

impl Handler for ReverseProxy {
    fn handle(&self, req: Request<Body>) -> Response<Body> {
        self.forward(req, None)
    }

    fn handle_connected(&self, info: &ConnectionInfo, req: Request<Body>) -> Response<Body> {
        self.forward(req, Some(info))
    }

    /// Forward a WebSocket upgrade, on routes that opted in with
    /// [`Route::upgrade`].
    ///
    /// Every way this can go wrong is an answer, not silence: a route that
    /// did not opt in falls through to the HTTP path (which answers `501`),
    /// and an upstream that cannot be dialled answers `502`. A client that
    /// is told why a WebSocket failed is a client that can say so.
    fn websocket(&self, req: &Request<Body>) -> WsUpgradeReply {
        if !crate::courierust_ws::is_websocket_upgrade(&req.headers) {
            return WsUpgradeReply::Pass;
        }
        let Some(entry) = self.entry_for(req) else {
            return WsUpgradeReply::Pass;
        };
        if !entry.route.upgrade {
            return WsUpgradeReply::Pass;
        }
        let slot = match self.reserve(entry, Instant::now()) {
            Pick::Ready(slot) => slot,
            Pick::NoUpstream => {
                return WsUpgradeReply::Refuse(self.error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "this route has no upstream",
                ))
            }
            Pick::AllBusy => {
                return WsUpgradeReply::Refuse(self.error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "every upstream of this route is at its in-flight limit",
                ))
            }
        };
        let base = &entry.route.upstreams[slot.index()].base;
        let url = upstream_ws_url(&entry.route, base, req);
        let options = ws_options(req);
        match WebSocket::connect_with(&url, self.client.config(), &options) {
            Ok(upstream) => {
                // The subprotocol is the upstream's decision, so it is the
                // upstream's answer that goes back to the client.
                let protocol = upstream.info().protocol.clone();
                // The reservation covers the handshake, not the life of the
                // socket: an upgrade is a request until it is answered, and
                // bounding the sockets themselves is the server's job
                // (`ServerConfig::max_connections`), not a backend's.
                slot.finish(true);
                WsUpgradeReply::AcceptWith {
                    service: Arc::new(WsBridge::new(upstream)),
                    protocol,
                }
            }
            Err(error) => {
                let message = error.to_string();
                slot.finish(false);
                WsUpgradeReply::Refuse(self.error(StatusCode::BAD_GATEWAY, &message))
            }
        }
    }
}

/// The upstream URL for a request.
///
/// One function for both legs: a route must not rewrite `/api` one way for
/// HTTP and another way for WebSocket, and the two callers differ only in the
/// scheme they need. The result is handed to the client, which parses it; a
/// base that cannot produce a usable URL therefore fails where every other
/// transport failure does, as a `502` naming the parse error.
fn upstream_url(route: &Route, base: &Url, req: &Request<Body>) -> String {
    format!(
        "{}://{}{}",
        base.scheme,
        base.authority(),
        target_path(route, base, req)
    )
}

/// The same target, as a `ws://`/`wss://` URL for the WebSocket client.
fn upstream_ws_url(route: &Route, base: &Url, req: &Request<Body>) -> String {
    let scheme = match base.scheme.as_str() {
        "https" => "wss",
        "http" => "ws",
        // Anything else is a scheme the WebSocket client cannot dial either;
        // it is passed through so that the failure names the real scheme
        // rather than a substitution this function invented.
        other => other,
    };
    format!(
        "{scheme}://{}{}",
        base.authority(),
        target_path(route, base, req)
    )
}

/// The request target on `base`: the upstream's own path, then whatever came
/// after the matched prefix, then the query.
///
/// Prefix and remainder are joined with exactly one slash, whatever either
/// side brought with it; the base's query, if it has one, is prepended to the
/// request's rather than glued in front of the path, which is what treating
/// `path_and_query` as a path would do.
fn target_path(route: &Route, base: &Url, req: &Request<Body>) -> String {
    // What is left of the path after the matched prefix.
    let rest = match &route.matcher {
        Matcher::Prefix(prefix) => {
            let cut = prefix.trim_end_matches('/').len().min(req.uri.path().len());
            req.uri.path()[cut..].to_string()
        }
        Matcher::Host(_) => req.uri.path().to_string(),
    };
    let mut target = String::from(base.path_and_query.path().trim_end_matches('/'));
    if rest.is_empty() {
        if target.is_empty() {
            target.push('/');
        }
    } else {
        if !rest.starts_with('/') {
            target.push('/');
        }
        target.push_str(&rest);
    }
    match (base.path_and_query.query(), req.uri.query()) {
        (Some(base_query), Some(query)) => {
            target.push('?');
            target.push_str(base_query);
            target.push('&');
            target.push_str(query);
        }
        (Some(query), None) | (None, Some(query)) => {
            target.push('?');
            target.push_str(query);
        }
        (None, None) => {}
    }
    target
}

/// Only the client's own handshake inputs cross to the upstream.
///
/// It keeps its subprotocol offer and the headers a WebSocket endpoint
/// authenticates on — a backend that never sees `Authorization` cannot
/// authorise anything — while the `Sec-WebSocket-*` fields stay behind:
/// they describe *this* handshake, and the client builds its own for the
/// upstream. `Origin` is one of the headers that cross, but through the
/// field that carries it rather than as a second copy in the list.
fn ws_options(req: &Request<Body>) -> WsClientOptions {
    let mut options = WsClientOptions {
        protocols: req
            .headers
            .get("sec-websocket-protocol")
            .and_then(|value| value.to_str().ok())
            .map(split_protocols)
            .unwrap_or_default(),
        origin: req
            .headers
            .get("origin")
            .and_then(|value| value.to_str().ok())
            .map(str::to_string),
        // Compression is offered upstream only when the client asked us for
        // it: the bridge decodes both legs, so compressing a leg nobody asked
        // to have compressed is CPU spent on nothing.
        compression: req.headers.contains_key("sec-websocket-extensions"),
        ..Default::default()
    };
    for (name, value) in req.headers.iter() {
        let literal = name.as_str();
        if is_hop_by_hop_for(&req.headers, literal)
            || literal == "host"
            || literal == "origin"
            || literal.starts_with("sec-websocket-")
            || matches!(
                literal,
                "via" | "x-forwarded-for" | "x-forwarded-proto" | "x-forwarded-host"
            )
        {
            continue;
        }
        if let Ok(value) = value.to_str() {
            options
                .headers
                .push((literal.to_string(), value.to_string()));
        }
    }
    options
}

/// Whether a header belongs only to this connection.
///
/// RFC 9110 lets `Connection` name additional hop-by-hop fields beyond the
/// standard list. Every value is considered because repeated `Connection`
/// fields are equivalent to one comma-joined field.
fn is_hop_by_hop_for(headers: &HeaderMap, name: &str) -> bool {
    is_hop_by_hop(name)
        || headers
            .iter()
            .filter(|(candidate, _)| candidate.as_str().eq_ignore_ascii_case("connection"))
            .any(|(_, value)| {
                value.to_str().ok().is_some_and(|tokens| {
                    tokens
                        .split(',')
                        .any(|token| token.trim().eq_ignore_ascii_case(name))
                })
            })
}

/// A `Sec-WebSocket-Protocol` value as a list.
fn split_protocols(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(str::to_string)
        .collect()
}

/// A proxied WebSocket connection.
///
/// The client leg is driven by the server (this is a [`WsService`]); the
/// upstream leg is driven by [`pump`] on its own thread. Writes in both
/// directions go through the upstream's shared writer, which is what lets
/// one thread read while another writes.
struct WsBridge {
    /// Taken by `on_open`, which is the first moment there is a [`WsSender`]
    /// to pump the upstream into.
    upstream: Mutex<Option<WebSocket>>,
    writer: WsClientWriter,
    stop: Arc<AtomicBool>,
}

impl WsBridge {
    fn new(upstream: WebSocket) -> Self {
        Self {
            writer: upstream.writer(),
            upstream: Mutex::new(Some(upstream)),
            stop: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl WsService for WsBridge {
    fn on_open(&self, c: &mut WsConn) {
        let Some(upstream) = crate::lock(&self.upstream).take() else {
            let _ = c.close(1011, "the upstream connection was already taken");
            return;
        };
        let client = c.sender();
        let stop = Arc::clone(&self.stop);
        std::thread::spawn(move || pump(upstream, client, stop));
    }

    fn on_message(&self, c: &mut WsConn, msg: WsData) {
        let sent = match &msg {
            WsData::Text(text) => self.writer.send_text(text),
            WsData::Binary(bytes) => self.writer.send_binary(bytes.as_slice()),
        };
        if sent.is_err() {
            // The upstream is gone; saying so with a close frame is the only
            // way the client learns the difference between "quiet" and
            // "broken".
            let _ = c.close(1011, "the upstream connection failed");
        }
    }

    fn on_close(&self, _c: &mut WsConn, _code: Option<u16>, _clean: bool) {
        // `pump` notices within one read timeout and closes the upstream.
        self.stop.store(true, Ordering::SeqCst);
    }
}

/// How long `pump` blocks in one go before it re-checks whether the client
/// leg is gone.
///
/// A blocking read that returned only when the upstream spoke would keep this
/// thread alive for as long as the upstream holds a silent connection open,
/// which is the common case for an idle WebSocket.
const PUMP_POLL: Duration = Duration::from_millis(200);

/// Carry the upstream's messages to the client until either end goes away.
fn pump(mut upstream: WebSocket, client: WsSender, stop: Arc<AtomicBool>) {
    let _ = upstream.set_read_timeout(Some(PUMP_POLL));
    loop {
        if stop.load(Ordering::SeqCst) {
            let _ = upstream.close(1001, "the client went away");
            return;
        }
        match upstream.poll_message() {
            Ok(Some(Event::Text(text))) => {
                if client.send_text(&text).is_err() {
                    return;
                }
            }
            Ok(Some(Event::Binary(bytes))) => {
                if client.send_binary(bytes.as_slice()).is_err() {
                    return;
                }
            }
            // Each leg's own session answers its peer's Ping, and a control
            // frame belongs to the connection it arrived on: relaying one
            // would make the client answer the upstream's keepalive through
            // this process for no reason.
            Ok(Some(Event::Ping(_))) | Ok(Some(Event::Pong(_))) => {}
            Ok(Some(Event::Close(frame))) => {
                match frame {
                    Some(frame) => {
                        let _ = client.close(frame.code, &frame.reason);
                    }
                    None => {
                        let _ = client.close(1005, "");
                    }
                }
                return;
            }
            // A read timeout: nothing to forward, and another chance to see
            // that the client leg ended.
            Ok(None) => {}
            Err(_) => {
                let _ = client.close(1011, "the upstream connection failed");
                return;
            }
        }
    }
}

/// Whether `path` is at or under `prefix`, on a segment boundary.
fn prefix_match(path: &str, prefix: &str) -> bool {
    if prefix == "/" {
        return true;
    }
    let prefix = prefix.trim_end_matches('/');
    match path.strip_prefix(prefix) {
        Some("") => true,
        Some(rest) => rest.starts_with('/'),
        None => false,
    }
}

/// Whether a request asks for a connection upgrade.
fn is_upgrade(headers: &HeaderMap) -> bool {
    headers.contains_key("upgrade")
        || headers
            .get("connection")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|value| {
                value
                    .split(',')
                    .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
            })
}

/// A body has to be materialized before it can be forwarded: the client has
/// one chance to send it, and a streaming body would have to be pulled from
/// the client's connection while the upstream connection is already open.
fn collect_body(body: Body, max: usize) -> Result<Vec<u8>, Error> {
    match body {
        Body::Empty => Ok(Vec::new()),
        // `Bytes` is already in memory, but the limit belongs to the proxy,
        // not to the server that read the body: a server configured
        // generously must not make the route's own limit decorative.
        Body::Bytes(bytes) if bytes.len() > max => Err(Error::protocol(format!(
            "the request body is {} bytes, over this proxy's {max}-byte limit",
            bytes.len()
        ))),
        Body::Bytes(bytes) => Ok(bytes.to_vec()),
        other => Ok(other.collect_limited(max)?.to_vec()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::courierust_client::ClientConfig;
    use crate::courierust_http::method::Method;

    #[test]
    fn response_body_limit_is_applied_before_protocol_reading() {
        let client = Client::with_config(ClientConfig {
            max_body: 4096,
            ..Default::default()
        });
        let proxy = ReverseProxy::new(client)
            .body_limit(1024)
            .body_limit(8192)
            .body_limit(512);

        assert_eq!(proxy.max_body, 512);
        assert_eq!(proxy.client.config().max_body, 512);
    }

    fn proxy_with(upstreams: &[&str], balance: Balance, health: HealthPolicy) -> ReverseProxy {
        ReverseProxy::new(Client::new()).health(health).balanced(
            Matcher::Prefix("/".to_string()),
            balance,
            upstreams.iter().map(|base| Url::parse(base).unwrap()),
        )
    }

    fn request(target: &'static str) -> Request<Body> {
        Request::<Body>::new(Method::GET, target)
    }

    /// Reserve an upstream and give it straight back, as a completed request
    /// would, returning which one was chosen.
    fn take(proxy: &ReverseProxy, entry: &RouteEntry, now: Instant, reached: bool) -> usize {
        match proxy.reserve(entry, now) {
            Pick::Ready(slot) => {
                let index = slot.index();
                slot.finish(reached);
                index
            }
            Pick::NoUpstream => panic!("the route has no upstreams"),
            Pick::AllBusy => panic!("every upstream is at its limit"),
        }
    }

    /// A proxy whose single route carries explicit in-flight limits, one per
    /// base.
    fn proxy_limited(bases: &[&str], limits: &[usize], balance: Balance) -> ReverseProxy {
        let upstreams = bases
            .iter()
            .zip(limits)
            .map(|(base, max)| Upstream::limited(Url::parse(base).unwrap(), *max));
        ReverseProxy::new(Client::new()).add_route(Route::balanced(
            Matcher::Prefix("/".to_string()),
            balance,
            upstreams,
        ))
    }

    #[test]
    fn round_robin_visits_every_upstream_before_repeating() {
        let proxy = proxy_with(
            &["http://a", "http://b", "http://c"],
            Balance::RoundRobin,
            HealthPolicy::default(),
        );
        let entry = &proxy.routes[0];
        let now = Instant::now();
        let mut picked = Vec::new();
        for _ in 0..7 {
            picked.push(take(&proxy, entry, now, true));
        }
        assert_eq!(picked, vec![0, 1, 2, 0, 1, 2, 0]);
    }

    #[test]
    fn least_connections_avoids_the_upstream_that_is_busy() {
        let proxy = proxy_with(
            &["http://a", "http://b"],
            Balance::LeastConnections,
            HealthPolicy::default(),
        );
        let entry = &proxy.routes[0];
        let now = Instant::now();
        // Hold the first upstream open, as a slow response would. Round robin
        // would hand it the second request anyway; this must not.
        let busy = match proxy.reserve(entry, now) {
            Pick::Ready(slot) => slot,
            _ => panic!("expected a reservation"),
        };
        assert_eq!(busy.index(), 0, "the rotation starts at the first upstream");
        for _ in 0..3 {
            assert_eq!(
                take(&proxy, entry, now, true),
                1,
                "the free upstream is the one to use"
            );
        }
        // Nothing is left in flight once the slow one finishes.
        busy.finish(true);
        let rotation = crate::lock(&entry.rotation);
        assert!(rotation.backends.iter().all(|b| b.in_flight == 0));
    }

    #[test]
    fn an_upstream_is_ejected_after_the_configured_failures() {
        let policy = HealthPolicy {
            failures: 2,
            cooldown: Duration::from_secs(30),
        };
        let proxy = proxy_with(&["http://a", "http://b"], Balance::RoundRobin, policy);
        let entry = &proxy.routes[0];
        let now = Instant::now();
        // One failure is not enough.
        proxy.release(entry, 0, false, now);
        proxy.release(entry, 0, false, now);
        assert!(crate::lock(&entry.rotation).backends[0].is_ejected(now));
        assert!(!crate::lock(&entry.rotation).backends[1].is_ejected(now));
        // It is skipped while it is out...
        assert_eq!(take(&proxy, entry, now, true), 1);
        // ...and it is back in rotation once the cooldown has passed, which
        // means a full round over the route includes it again.
        let later = now + Duration::from_secs(31);
        assert!(!crate::lock(&entry.rotation).backends[0].is_ejected(later));
        let mut picked = Vec::new();
        for _ in 0..2 {
            picked.push(take(&proxy, entry, later, true));
        }
        picked.sort_unstable();
        assert_eq!(picked, vec![0, 1]);
    }

    #[test]
    fn a_success_puts_an_upstream_back_in_the_rotation() {
        let proxy = proxy_with(
            &["http://a", "http://b"],
            Balance::RoundRobin,
            HealthPolicy {
                failures: 1,
                cooldown: Duration::from_secs(30),
            },
        );
        let entry = &proxy.routes[0];
        let now = Instant::now();
        proxy.release(entry, 0, false, now);
        let later = now + Duration::from_secs(31);
        let index = take(&proxy, entry, later, true);
        assert_eq!(index, 0, "the ejection expired");
        proxy.release(entry, 0, true, later);
        assert!(crate::lock(&entry.rotation).backends[0]
            .ejected_until
            .is_none());
    }

    #[test]
    fn ejection_off_means_a_failure_is_never_counted() {
        let proxy = proxy_with(
            &["http://a", "http://b"],
            Balance::RoundRobin,
            HealthPolicy {
                failures: 0,
                cooldown: Duration::from_secs(30),
            },
        );
        let entry = &proxy.routes[0];
        let now = Instant::now();
        for _ in 0..10 {
            proxy.release(entry, 0, false, now);
        }
        assert!(!crate::lock(&entry.rotation).backends[0].is_ejected(now));
        assert_eq!(take(&proxy, entry, now, true), 0);
    }

    #[test]
    fn the_longest_ejected_upstream_is_the_one_probed() {
        let proxy = proxy_with(
            &["http://a", "http://b"],
            Balance::RoundRobin,
            HealthPolicy {
                failures: 1,
                cooldown: Duration::from_secs(30),
            },
        );
        let entry = &proxy.routes[0];
        let now = Instant::now();
        // Both are out, and the first went out a millisecond earlier.
        proxy.release(entry, 0, false, now);
        proxy.release(entry, 1, false, now + Duration::from_millis(1));
        assert_eq!(
            take(&proxy, entry, now + Duration::from_millis(2), true),
            0,
            "with nothing healthy left, the oldest failure is the one to retry"
        );
    }

    #[test]
    fn an_upstream_stops_taking_requests_at_its_limit() {
        let proxy = proxy_limited(&["http://a", "http://b"], &[1, 0], Balance::RoundRobin);
        let entry = &proxy.routes[0];
        let now = Instant::now();
        let held = match proxy.reserve(entry, now) {
            Pick::Ready(slot) => slot,
            _ => panic!("expected a reservation"),
        };
        assert_eq!(held.index(), 0);
        // The cursor says "one" and one is full: the request goes to the
        // other upstream instead of waiting behind it.
        assert_eq!(take(&proxy, entry, now, true), 1);
        held.finish(true);
        assert_eq!(take(&proxy, entry, now, true), 0, "back under the limit");
    }

    #[test]
    fn a_route_whose_upstreams_are_all_full_is_busy_not_unlimited() {
        let proxy = proxy_limited(&["http://a", "http://b"], &[1, 1], Balance::RoundRobin);
        let entry = &proxy.routes[0];
        let now = Instant::now();
        let first = match proxy.reserve(entry, now) {
            Pick::Ready(slot) => slot,
            _ => panic!("expected a reservation"),
        };
        let second = match proxy.reserve(entry, now) {
            Pick::Ready(slot) => slot,
            _ => panic!("expected a reservation"),
        };
        assert!(
            matches!(proxy.reserve(entry, now), Pick::AllBusy),
            "a full upstream is not quietly exceeded"
        );
        first.finish(true);
        assert_eq!(second.index(), 1);
        second.finish(true);
        assert!(matches!(proxy.reserve(entry, now), Pick::Ready(_)));
    }

    #[test]
    fn a_limit_of_zero_means_no_limit() {
        let proxy = proxy_limited(&["http://a"], &[0], Balance::RoundRobin);
        let entry = &proxy.routes[0];
        let now = Instant::now();
        let mut held = Vec::new();
        for _ in 0..64 {
            match proxy.reserve(entry, now) {
                Pick::Ready(slot) => held.push(slot),
                _ => panic!("an unlimited upstream never runs out"),
            }
        }
        assert_eq!(crate::lock(&entry.rotation).backends[0].in_flight, 64);
        drop(held);
        assert_eq!(crate::lock(&entry.rotation).backends[0].in_flight, 0);
    }

    #[test]
    fn a_dropped_slot_gives_its_room_back_without_scoring_the_attempt() {
        let proxy = proxy_with(
            &["http://a"],
            Balance::RoundRobin,
            HealthPolicy {
                failures: 1,
                cooldown: Duration::from_secs(30),
            },
        );
        let entry = &proxy.routes[0];
        drop(match proxy.reserve(entry, Instant::now()) {
            Pick::Ready(slot) => slot,
            _ => panic!("expected a reservation"),
        });
        let rotation = crate::lock(&entry.rotation);
        assert_eq!(rotation.backends[0].in_flight, 0, "the room is back");
        assert_eq!(
            rotation.backends[0].failures, 0,
            "and nothing was blamed on the upstream"
        );
        assert!(!rotation.backends[0].is_ejected(Instant::now()));
    }

    #[test]
    fn a_route_with_no_upstreams_answers_503() {
        let proxy =
            ReverseProxy::new(Client::new()).route_all(prefix_matcher(), Vec::<Upstream>::new());
        let resp = proxy.handle(request("/x"));
        assert_eq!(resp.status.as_u16(), 503);
    }

    fn prefix_matcher() -> Matcher {
        Matcher::Prefix("/".to_string())
    }

    #[test]
    fn the_upstream_handshake_keeps_authentication_and_drops_the_frame_protocol() {
        let mut req = request("/ws");
        req.headers.insert(
            HeaderName::from_lowercase("authorization"),
            HeaderValue::from_static("Bearer t"),
        );
        req.headers.insert(
            HeaderName::from_lowercase("cookie"),
            HeaderValue::from_static("session=1"),
        );
        req.headers.insert(
            HeaderName::from_lowercase("sec-websocket-key"),
            HeaderValue::from_static("dGhlIHNhbXBsZSBub25jZQ=="),
        );
        req.headers.insert(
            HeaderName::from_lowercase("sec-websocket-protocol"),
            HeaderValue::from_static("chat, , superchat"),
        );
        req.headers.insert(
            HeaderName::from_lowercase("origin"),
            HeaderValue::from_static("https://app.example"),
        );

        let options = ws_options(&req);
        assert_eq!(options.protocols, vec!["chat", "superchat"]);
        assert_eq!(options.origin.as_deref(), Some("https://app.example"));
        assert!(options
            .headers
            .iter()
            .any(|(name, value)| name == "authorization" && value == "Bearer t"));
        assert!(options
            .headers
            .iter()
            .any(|(name, value)| name == "cookie" && value == "session=1"));
        assert!(
            !options
                .headers
                .iter()
                .any(|(name, _)| name.starts_with("sec-websocket-")),
            "the frame protocol describes this handshake, not the upstream's"
        );
        assert_eq!(
            options
                .headers
                .iter()
                .filter(|(name, _)| name == "origin")
                .count(),
            0,
            "origin crosses once, through the field that carries it"
        );
    }
}
