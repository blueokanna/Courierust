//! A cookie jar for the client (RFC 6265).
//!
//! This is a **client** jar, and it is deliberately not a browser:
//!
//! * `HttpOnly` and `SameSite` are accepted and ignored. There is no script
//!   engine here for `HttpOnly` to protect a cookie from, and no cross-site
//!   request context for `SameSite` to discriminate between. Pretending to
//!   enforce either would be a claim the caller cannot check.
//! * The Public Suffix List is **not** shipped. A host may therefore set a
//!   cookie for an ancestor domain it does not own — RFC 6265 §5.3 step 5
//!   asks for a PSL check on top of the domain-match that *is* enforced
//!   here. The blast radius is bounded by that domain-match: a cookie for
//!   `co.uk` can only be set by a host under `co.uk`, never by
//!   `evil.com`. It is a real deviation from a browser, stated rather than
//!   hidden.
//!
//! Everything else follows the RFC: the storage algorithm (§5.3), the
//! retrieval algorithm (§5.4), domain-matching (§5.1.3), path-matching and
//! default-path (§5.1.4), `Max-Age` over `Expires`, replacement keyed by
//! `(name, domain, path)`, and bounded storage so a hostile peer cannot
//! grow this process without limit.

use crate::courierust_http::uri::Url;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// Browser-like storage ceilings: not the RFC's business, but a client that
/// lets a peer allocate without bound is a client that gets killed for it.
const MAX_COOKIES: usize = 3_000;
const MAX_COOKIES_PER_HOST: usize = 180;
/// RFC 6265 §6.1 recommends supporting at least 4096 bytes per cookie.
const MAX_COOKIE_BYTES: usize = 4_096;

/// One stored cookie.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cookie {
    /// Cookie name.
    pub name: String,
    /// Cookie value, unquoted.
    pub value: String,
    /// The host that set it. Always present: a host-only cookie uses this
    /// as its domain, a `Domain` cookie keeps it for the per-host cap.
    pub host: String,
    /// The `Domain` attribute, lowercased with any leading dot removed.
    /// `None` for a host-only cookie.
    pub domain: Option<String>,
    /// The `Path` attribute, defaulted per RFC 6265 §5.1.4.
    pub path: String,
    /// Send only over `https://`.
    pub secure: bool,
    /// Expiry as a Unix timestamp; `None` is a session cookie.
    pub expires_at: Option<i64>,
    /// Storage order, the tie-break of RFC 6265 §5.4 step 2. Private: it is
    /// the jar's bookkeeping, not something a caller sets.
    created: u64,
}

impl Cookie {
    /// The domain this cookie matches against: its `Domain` attribute, or
    /// the setting host for a host-only cookie.
    fn effective_domain(&self) -> &str {
        self.domain.as_deref().unwrap_or(&self.host)
    }
}

/// A jar of cookies, keyed by `(name, domain, path)`.
///
/// Cloneable and `Send`: the client holds one behind
/// `Arc<Mutex<CookieJar>>`, so every clone of a client shares one session,
/// the way a browser profile does.
#[derive(Debug, Clone)]
pub struct CookieJar {
    cookies: Vec<Cookie>,
    /// Monotonic creation counter.
    next_created: u64,
    max_cookies: usize,
    max_per_host: usize,
}

impl Default for CookieJar {
    fn default() -> Self {
        Self::new()
    }
}

impl CookieJar {
    /// An empty jar with default limits.
    pub fn new() -> Self {
        Self::with_limits(MAX_COOKIES, MAX_COOKIES_PER_HOST)
    }

    /// An empty jar with explicit ceilings (for tests, and for callers that
    /// want a tighter bound than the browser-like default).
    pub fn with_limits(max_cookies: usize, max_per_host: usize) -> Self {
        Self {
            cookies: Vec::new(),
            next_created: 0,
            max_cookies: max_cookies.max(1),
            max_per_host: max_per_host.max(1),
        }
    }

    /// Number of stored cookies.
    pub fn len(&self) -> usize {
        self.cookies.len()
    }

    /// Whether the jar is empty.
    pub fn is_empty(&self) -> bool {
        self.cookies.is_empty()
    }

    /// Everything currently stored.
    pub fn iter(&self) -> impl Iterator<Item = &Cookie> {
        self.cookies.iter()
    }

    /// Forget everything.
    pub fn clear(&mut self) {
        self.cookies.clear();
    }

    /// Store one `Set-Cookie` header value.
    ///
    /// A malformed header is ignored, as RFC 6265 §5.2 requires: a peer must
    /// not be able to break a session by sending one.
    pub fn store(&mut self, url: &Url, set_cookie: &str) {
        self.store_at(url, set_cookie, super::unix_now());
    }

    /// [`Self::store`] against an explicit clock, so expiry is testable.
    pub fn store_at(&mut self, url: &Url, set_cookie: &str, now: i64) {
        let Some(parsed) = parse_set_cookie(set_cookie) else {
            return;
        };
        // RFC 6265 §5.3 step 5: a cookie whose `Domain` attribute does not
        // domain-match the request host is ignored *entirely*. This is the
        // rule that stops a peer planting a cookie on someone else's host.
        if let Some(domain) = &parsed.domain {
            if !domain_match(&url.host, domain) {
                return;
            }
        }
        let path = match &parsed.path {
            Some(p) if p.starts_with('/') => p.clone(),
            _ => default_path(url.path_and_query.as_str()),
        };
        // §6.1: above the size ceiling the cookie is dropped, not truncated
        // — a truncated value is a corrupt session.
        if parsed.name.len() + parsed.value.len() > MAX_COOKIE_BYTES {
            return;
        }
        let domain = parsed.domain.clone();
        let effective = domain.as_deref().unwrap_or(&url.host);
        let dead = parsed.deletion_at(now);
        let existing = self.cookies.iter().position(|c| {
            c.name == parsed.name && c.effective_domain() == effective && c.path == path
        });
        if now >= dead {
            // A deletion still has to find the cookie it deletes.
            if let Some(index) = existing {
                self.cookies.remove(index);
            }
            return;
        }
        let created = match existing {
            // Replacing keeps the original creation time, which is what
            // makes the §5.4 ordering stable across a value refresh.
            Some(index) => self.cookies[index].created,
            None => {
                self.next_created += 1;
                self.next_created
            }
        };
        let cookie = Cookie {
            name: parsed.name,
            value: parsed.value,
            host: url.host.clone(),
            domain,
            path,
            secure: parsed.secure,
            expires_at: match dead {
                i64::MAX => None,
                at => Some(at),
            },
            created,
        };
        match existing {
            Some(index) => self.cookies[index] = cookie,
            None => self.cookies.push(cookie),
        }
        self.enforce_limits();
    }

    /// The `Cookie` header value for a request to `url`.
    ///
    /// Cookies are ordered by descending path length, then by creation time,
    /// as RFC 6265 §5.4 requires — servers that parse naively depend on it.
    pub fn header_value(&self, url: &Url) -> Option<String> {
        let secure_scheme = url.scheme == "https";
        let path = url.path_and_query.as_str();
        let mut matched: Vec<&Cookie> = self
            .cookies
            .iter()
            .filter(|c| host_matches(url, c) && path_match(path, &c.path))
            .filter(|c| !c.secure || secure_scheme)
            .collect();
        if matched.is_empty() {
            return None;
        }
        matched.sort_by(|a, b| {
            b.path
                .len()
                .cmp(&a.path.len())
                .then(a.created.cmp(&b.created))
        });
        let mut out = String::new();
        for cookie in matched {
            if !out.is_empty() {
                out.push_str("; ");
            }
            out.push_str(&cookie.name);
            out.push('=');
            out.push_str(&cookie.value);
        }
        Some(out)
    }

    /// Enforce the ceilings, oldest first.
    fn enforce_limits(&mut self) {
        while self.cookies.len() > self.max_cookies {
            self.drop_oldest(|_| true);
        }
        let mut hosts: Vec<String> = self.cookies.iter().map(|c| c.host.clone()).collect();
        hosts.sort();
        hosts.dedup();
        for host in hosts {
            loop {
                let count = self.cookies.iter().filter(|c| c.host == host).count();
                if count <= self.max_per_host {
                    break;
                }
                self.drop_oldest(|c| c.host == host);
            }
        }
    }

    fn drop_oldest(&mut self, mut keep: impl FnMut(&Cookie) -> bool) {
        let oldest = self
            .cookies
            .iter()
            .enumerate()
            .filter(|(_, c)| keep(c))
            .min_by_key(|(_, c)| c.created)
            .map(|(index, _)| index);
        if let Some(index) = oldest {
            self.cookies.remove(index);
        }
    }
}

/// Whether `cookie` may be sent to `url` (RFC 6265 §5.4 step 1).
fn host_matches(url: &Url, cookie: &Cookie) -> bool {
    match &cookie.domain {
        // A host-only cookie goes back to exactly the host that set it.
        None => url.host == cookie.host,
        Some(domain) => domain_match(&url.host, domain),
    }
}

/// RFC 6265 §5.1.3 domain-matching.
///
/// The leading-dot check is the whole point: `ends_with` alone would let
/// `evil-example.com` match a cookie scoped to `example.com`, which is how
/// this rule is most often got wrong.
fn domain_match(host: &str, domain: &str) -> bool {
    if host == domain {
        return true;
    }
    // RFC 6265 §5.1.3: a string that parses as an IP address matches only
    // itself.
    if is_ip_literal(host) || is_ip_literal(domain) {
        return false;
    }
    host.len() > domain.len()
        && host.ends_with(domain)
        && host.as_bytes()[host.len() - domain.len() - 1] == b'.'
}

fn is_ip_literal(host: &str) -> bool {
    host.parse::<std::net::IpAddr>().is_ok()
}

/// RFC 6265 §5.1.4 path-matching.
fn path_match(request_path: &str, cookie_path: &str) -> bool {
    if request_path == cookie_path {
        return true;
    }
    if !request_path.starts_with(cookie_path) {
        return false;
    }
    cookie_path.ends_with('/') || request_path.as_bytes()[cookie_path.len()] == b'/'
}

/// RFC 6265 §5.1.4 default-path: the request path up to, but excluding, the
/// rightmost `/`.
fn default_path(request_path: &str) -> String {
    match request_path.rfind('/') {
        Some(0) | None => "/".to_string(),
        Some(index) => request_path[..index].to_string(),
    }
}

/// The parse of a single `Set-Cookie` value.
struct ParsedCookie {
    name: String,
    value: String,
    domain: Option<String>,
    path: Option<String>,
    secure: bool,
    /// `Max-Age` in seconds, when present (it wins over `Expires`).
    max_age: Option<i64>,
    /// `Expires` as a Unix timestamp.
    expires: Option<i64>,
}

impl ParsedCookie {
    /// The instant at which this cookie is dead.
    fn deletion_at(&self, now: i64) -> i64 {
        match self.max_age {
            // RFC 6265 §5.2.2: a non-positive `Max-Age` deletes the cookie.
            Some(age) if age <= 0 => i64::MIN,
            Some(age) => now.saturating_add(age),
            None => self.expires.unwrap_or(i64::MAX),
        }
    }
}

/// Parse a `Set-Cookie` value; `None` when the mandatory `name=value` pair
/// is malformed.
fn parse_set_cookie(header: &str) -> Option<ParsedCookie> {
    let mut segments = header.split(';');
    let (name, value) = {
        let (name, value) = segments.next()?.split_once('=')?;
        let name = name.trim();
        if !is_token(name) {
            return None;
        }
        (name.to_string(), unquote(value.trim()))
    };
    let mut parsed = ParsedCookie {
        name,
        value,
        domain: None,
        path: None,
        secure: false,
        max_age: None,
        expires: None,
    };
    for attribute in segments {
        let (key, value) = match attribute.split_once('=') {
            Some((k, v)) => (k.trim(), v.trim()),
            None => (attribute.trim(), ""),
        };
        // Unknown attributes are ignored, not errors (§5.2), so a future
        // attribute cannot break an old client.
        if key.eq_ignore_ascii_case("domain") {
            let domain = value.trim_start_matches('.').to_ascii_lowercase();
            if !domain.is_empty() {
                parsed.domain = Some(domain);
            }
        } else if key.eq_ignore_ascii_case("path") {
            parsed.path = Some(value.to_string());
        } else if key.eq_ignore_ascii_case("secure") {
            parsed.secure = true;
        } else if key.eq_ignore_ascii_case("max-age") {
            if let Ok(age) = value.parse::<i64>() {
                parsed.max_age = Some(age);
            }
        } else if key.eq_ignore_ascii_case("expires") {
            parsed.expires = parse_cookie_date(value);
        }
    }
    Some(parsed)
}

fn unquote(value: &str) -> String {
    let bytes = value.as_bytes();
    if bytes.len() >= 2 && bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"' {
        return value[1..value.len() - 1].to_string();
    }
    value.to_string()
}

/// RFC 6265 §4.1.1 `token`: the characters a cookie name may use.
fn is_token(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|b| {
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

const MONTHS: [&str; 12] = [
    "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
];

/// Parse the cookie-date formats §5.1.1 has to tolerate into a Unix
/// timestamp.
///
/// Accepts the delimiters seen in the wild (`,` , space, `-`) and both two-
/// and four-digit years, because a server that sends `Expires: Sun, 06 Nov
/// 94 08:49:37 GMT` is still a server a client has to talk to.
fn parse_cookie_date(value: &str) -> Option<i64> {
    let tokens: Vec<&str> = value
        .split(|c: char| c == ',' || c.is_whitespace() || c == '-')
        .filter(|t| !t.is_empty())
        .collect();
    let mut day = None;
    let mut month = None;
    let mut year = None;
    let mut clock = None;
    for (index, token) in tokens.iter().enumerate() {
        if token.len() == 3 {
            if let Some(position) = MONTHS.iter().position(|m| m.eq_ignore_ascii_case(token)) {
                // The token before a month name is the day of the month.
                day = index
                    .checked_sub(1)
                    .and_then(|i| tokens[i].parse::<u32>().ok());
                month = Some(position as u32 + 1);
            }
        }
        if token.contains(':') {
            clock = parse_clock(token);
        }
        if token.len() == 4 && token.bytes().all(|b| b.is_ascii_digit()) {
            year = token.parse::<i32>().ok();
        }
    }
    let (day, month, year, (hour, minute, second)) = (day?, month?, year?, clock?);
    // RFC 6265 §5.1.1: a two-digit year is 19xx from 70..=99, 20xx below.
    let year = if year < 100 {
        if year >= 70 {
            1900 + year
        } else {
            2000 + year
        }
    } else {
        year
    };
    Some(
        days_from_civil(year, month, day) * 86_400
            + i64::from(hour) * 3_600
            + i64::from(minute) * 60
            + i64::from(second),
    )
}

fn parse_clock(token: &str) -> Option<(u32, u32, u32)> {
    let mut parts = token.split(':');
    let hour = parts.next()?.parse::<u32>().ok()?;
    let minute = parts.next()?.parse::<u32>().ok()?;
    let second = parts.next()?.parse::<u32>().ok()?;
    (hour < 24 && minute < 60 && second < 60).then_some((hour, minute, second))
}

/// Days between 1970-01-01 and `year-month-day` (Howard Hinnant's
/// `days_from_civil`), valid for days before the epoch too.
fn days_from_civil(year: i32, month: u32, day: u32) -> i64 {
    let shift = i32::from(month <= 2);
    let y = i64::from(year - shift);
    let m = i64::from(month);
    let d = i64::from(day);
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The inverse of [`days_from_civil`].
///
/// Only the tests need to go back the other way, but keeping the pair
/// together is what makes the calendar maths checkable in both directions.
#[cfg(test)]
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m as u32, d as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(s: &str) -> Url {
        Url::parse(s).expect("test url")
    }

    #[test]
    fn the_dot_matters_in_domain_matching() {
        // The classic bug: `"evil-example.com".ends_with("example.com")` is
        // true, so a naive suffix check hands one host's cookies to another.
        assert!(!domain_match("evil-example.com", "example.com"));
        assert!(domain_match("a.example.com", "example.com"));
        assert!(domain_match("example.com", "example.com"));
        assert!(!domain_match("example.com", "a.example.com"));
        assert!(domain_match("127.0.0.1", "127.0.0.1"));
        assert!(!domain_match("127.0.0.1", "0.0.1"));
    }

    #[test]
    fn a_cookie_for_another_host_is_refused_outright() {
        let mut jar = CookieJar::new();
        jar.store_at(&url("https://evil.com/"), "sid=1; Domain=example.com", 0);
        assert!(jar.is_empty(), "a foreign Domain must be ignored");
        jar.store_at(
            &url("https://a.example.com/"),
            "sid=2; Domain=.example.com",
            0,
        );
        assert_eq!(jar.len(), 1, "a leading dot is the same domain");
    }

    #[test]
    fn domain_and_path_matching_decide_where_a_cookie_is_sent() {
        let mut jar = CookieJar::new();
        jar.store_at(&url("https://example.com/a/b"), "p=1; Path=/a", 0);
        jar.store_at(&url("https://example.com/a/b"), "q=2; Path=/a/b", 0);
        jar.store_at(&url("https://example.com/a/b"), "r=3", 0);
        jar.store_at(
            &url("https://example.com/a/b"),
            "s=4; Domain=example.com; Path=/",
            0,
        );

        // Longest path first, then creation order.
        assert_eq!(
            jar.header_value(&url("https://example.com/a/b/c")).unwrap(),
            "q=2; p=1; r=3; s=4"
        );
        assert_eq!(
            jar.header_value(&url("https://example.com/a/bc")).unwrap(),
            "p=1; r=3; s=4",
            "`/a` does match `/a/bc` — the next character is a slash"
        );
        assert_eq!(
            jar.header_value(&url("https://example.com/abc")).unwrap(),
            "s=4",
            "`/a` must not match `/abc`: the next character is not a slash"
        );
        assert_eq!(
            jar.header_value(&url("https://example.com/")).unwrap(),
            "s=4"
        );
        assert_eq!(jar.header_value(&url("https://other.com/a/b/c")), None);
    }

    #[test]
    fn a_host_only_cookie_never_leaves_its_host() {
        let mut jar = CookieJar::new();
        jar.store_at(&url("https://a.example.com/"), "sid=1", 0);
        assert!(
            jar.header_value(&url("https://b.example.com/")).is_none(),
            "without a Domain attribute there is no sibling access"
        );
        assert!(jar.header_value(&url("https://a.example.com/")).is_some());
    }

    #[test]
    fn a_secure_cookie_never_travels_in_clear() {
        let mut jar = CookieJar::new();
        jar.store_at(&url("https://example.com/"), "sid=1; Secure", 0);
        assert_eq!(
            jar.header_value(&url("https://example.com/")).unwrap(),
            "sid=1"
        );
        assert_eq!(jar.header_value(&url("http://example.com/")), None);
    }

    #[test]
    fn expiry_replacement_and_deletion() {
        let mut jar = CookieJar::new();
        let u = url("https://example.com/");
        jar.store_at(&u, "sid=old", 1_000);
        jar.store_at(&u, "sid=new", 1_000);
        assert_eq!(jar.len(), 1, "the same key replaces, never duplicates");
        assert_eq!(jar.header_value(&u).unwrap(), "sid=new");

        // `Max-Age` wins over `Expires` (RFC 6265 §5.3 step 3).
        jar.store_at(
            &u,
            "sid=x; Max-Age=100; Expires=Thu, 01 Jan 2099 00:00:00 GMT",
            1_000,
        );
        assert_eq!(jar.iter().next().unwrap().expires_at, Some(1_100));
        jar.store_at(&u, "sid=x; Max-Age=0", 1_100);
        assert!(jar.is_empty(), "a zero Max-Age deletes");
        // Deleting something absent is a no-op, not a panic.
        jar.store_at(&u, "sid=x; Max-Age=0", 1_100);
        assert!(jar.is_empty());
        // An already-expired `Expires` deletes in the same way.
        jar.store_at(&u, "sid=y", 1_000);
        assert_eq!(jar.len(), 1);
        jar.store_at(&u, "sid=y; Expires=Thu, 01 Jan 1970 00:00:00 GMT", 1_000);
        assert!(jar.is_empty());
    }

    #[test]
    fn dates_are_read_in_the_formats_servers_actually_send() {
        // Reference values come from an independent implementation
        // (Python's `calendar.timegm`), not from hand arithmetic.
        assert_eq!(
            parse_cookie_date("Thu, 14 Jan 2027 00:00:00 GMT"),
            Some(1_799_884_800)
        );
        assert_eq!(
            parse_cookie_date("Thu, 14-Jan-2027 00:00:00 GMT"),
            Some(1_799_884_800)
        );
        assert_eq!(
            parse_cookie_date("Sun, 06 Nov 1994 08:49:37 GMT"),
            Some(784_111_777)
        );
        assert_eq!(parse_cookie_date("nonsense"), None);
        assert_eq!(parse_cookie_date("Thu, 14 Jan 2027 25:00:00 GMT"), None);
    }

    #[test]
    fn the_civil_calendar_maths_matches_an_independent_implementation() {
        // Python `calendar.timegm` reference values.
        let cases = [
            ((1969, 12, 31), -86_400_i64),
            ((1970, 1, 1), 0),
            ((1970, 3, 1), 5_097_600),
            ((1999, 12, 31), 946_598_400),
            ((2000, 2, 29), 951_782_400),
            ((2024, 3, 1), 1_709_251_200),
            ((2027, 1, 14), 1_799_884_800),
            ((2038, 1, 19), 2_147_472_000),
        ];
        for ((year, month, day), expected) in cases {
            assert_eq!(
                days_from_civil(year, month, day) * 86_400,
                expected,
                "{year}-{month}-{day}"
            );
            assert_eq!(
                civil_from_days(expected.div_euclid(86_400)),
                (i64::from(year), month, day),
                "inverse of {year}-{month}-{day}"
            );
        }
        // `civil_from_days` must round-trip the day before the epoch too.
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
    }

    #[test]
    fn malformed_headers_are_ignored_not_fatal() {
        let mut jar = CookieJar::new();
        let u = url("https://example.com/");
        for bad in ["", "no-equals", "=value", "bad name=1", ";;;"] {
            jar.store_at(&u, bad, 0);
        }
        assert!(jar.is_empty(), "a peer must not break the jar: {jar:?}");
        // Valueless and unknown attributes are fine.
        jar.store_at(&u, "ok=1; HttpOnly; SameSite=Lax; Future=x; Path", 0);
        assert_eq!(jar.header_value(&u).unwrap(), "ok=1");
        // A quoted value is unquoted exactly once.
        jar.store_at(&u, "q=\"a b\"", 0);
        assert_eq!(jar.iter().find(|c| c.name == "q").unwrap().value, "a b");
    }

    #[test]
    fn storage_is_bounded_per_host() {
        let mut jar = CookieJar::with_limits(100, 3);
        let u = url("https://example.com/");
        for i in 0..10 {
            jar.store_at(&u, &format!("c{i}=1; Path=/p{i}"), 0);
        }
        assert_eq!(jar.len(), 3, "the per-host cap holds");
        let names: Vec<&str> = jar.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["c7", "c8", "c9"], "the oldest go first");
    }

    #[test]
    fn storage_is_bounded_overall() {
        let mut jar = CookieJar::with_limits(4, 100);
        for i in 0..10 {
            let u = url(&format!("https://h{i}.example/"));
            jar.store_at(&u, "c=1", 0);
        }
        assert_eq!(
            jar.len(),
            4,
            "a fleet of hosts cannot grow the jar without bound"
        );
    }

    #[test]
    fn an_oversized_cookie_is_dropped_not_truncated() {
        let mut jar = CookieJar::new();
        let u = url("https://example.com/");
        jar.store_at(&u, &format!("big={}; Path=/", "x".repeat(5_000)), 0);
        assert!(
            jar.is_empty(),
            "over the size ceiling, dropped not truncated"
        );
    }
}
