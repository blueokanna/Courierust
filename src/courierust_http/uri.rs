//! Request target (path + query) and absolute URL parsing.

use crate::courierust_bytes::Bytes;
use crate::courierust_error::{Error, Result};
use alloc::string::String;
use alloc::string::ToString;
use core::fmt;

/// A request target: path + optional query, origin-form (`/x?y`),
/// asterisk-form (`*`) or absolute-form (proxy).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PathAndQuery(Bytes);

impl PathAndQuery {
    /// Parse a target. Origin-form must start with `/`; asterisk-form is
    /// exactly `*`; absolute-form (`scheme://host/path`) is accepted and
    /// stored verbatim.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.is_empty() {
            return Err(Error::protocol("empty request target"));
        }
        if b == b"*" || b[0] == b'/' || b[0] == b'?' {
            // Validate there are no control characters.
            if b.iter().any(|&c| c < 0x20 || c == 0x7f) {
                return Err(Error::protocol("control character in request target"));
            }
            return Ok(Self(Bytes::from(b)));
        }
        let s = core::str::from_utf8(b).map_err(|_| Error::protocol("non-UTF8 absolute target"))?;
        if b.iter().any(|&c| c < 0x20 || c == 0x7f) {
            return Err(Error::protocol("control character in request target"));
        }
        let (scheme, rest) = s
            .split_once("://")
            .ok_or_else(|| Error::protocol("invalid request target form"))?;
        if scheme.is_empty() || rest.is_empty() {
            return Err(Error::protocol("invalid absolute target"));
        }
        Ok(Self(Bytes::from(b)))
    }

    /// A static target (assumed valid).
    #[inline]
    pub fn from_static(s: &'static str) -> Self {
        Self(Bytes::from_static(s.as_bytes()))
    }

    /// The path component (without query), UTF-8.
    pub fn path(&self) -> &str {
        let s = self.as_str();
        s.split('?').next().unwrap_or(s)
    }

    /// The raw query string, if any.
    pub fn query(&self) -> Option<&str> {
        let s = self.as_str();
        s.split_once('?').map(|(_, q)| q)
    }

    /// Full target as a string.
    pub fn as_str(&self) -> &str {
        match core::str::from_utf8(self.0.as_slice()) {
            Ok(s) => s,
            Err(_) => "<non-utf8 target>",
        }
    }

    /// Raw bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl fmt::Display for PathAndQuery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Debug for PathAndQuery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PathAndQuery({})", self.as_str())
    }
}

impl From<&'static str> for PathAndQuery {
    fn from(s: &'static str) -> Self {
        Self::from_static(s)
    }
}

impl core::str::FromStr for PathAndQuery {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::from_bytes(s.as_bytes())
    }
}

/// An absolute URL with the pieces the stack needs to route and connect.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Url {
    /// Scheme, lowercased (only `http` is directly connectable here).
    pub scheme: String,
    /// Host, lowercased.
    pub host: String,
    /// Port (defaulted from scheme when absent).
    pub port: u16,
    /// Path + query.
    pub path_and_query: PathAndQuery,
    /// Raw userinfo, if present (unsupported for connection).
    pub userinfo: Option<String>,
}

fn contains_forbidden_authority_byte(value: &str) -> bool {
    value
        .bytes()
        .any(|byte| byte <= b' ' || byte == 0x7f || matches!(byte, b'/' | b'?' | b'#' | b'@'))
}

fn parse_port(value: &str) -> Result<u16> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Error::protocol(
            "URL port must be a non-zero decimal number",
        ));
    }
    let port = value
        .parse::<u16>()
        .map_err(|_| Error::protocol("URL port is out of range"))?;
    if port == 0 {
        return Err(Error::protocol("URL port must not be zero"));
    }
    Ok(port)
}

fn parse_host_and_port(authority: &str, default_port: u16) -> Result<(String, u16)> {
    if authority.is_empty() {
        return Err(Error::protocol("URL missing host"));
    }

    if let Some(bracketed) = authority.strip_prefix('[') {
        let closing = bracketed
            .find(']')
            .ok_or_else(|| Error::protocol("URL IPv6 host is missing closing bracket"))?;
        let host = &bracketed[..closing];
        let suffix = &bracketed[closing + 1..];
        if host.is_empty() || contains_forbidden_authority_byte(host) {
            return Err(Error::protocol("invalid URL host"));
        }
        let port = if suffix.is_empty() {
            default_port
        } else if let Some(value) = suffix.strip_prefix(':') {
            parse_port(value)?
        } else {
            return Err(Error::protocol("invalid URL authority after IPv6 host"));
        };
        return Ok((host.to_ascii_lowercase(), port));
    }

    if authority.contains(['[', ']']) {
        return Err(Error::protocol("invalid URL host brackets"));
    }

    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => {
            if host.contains(':') {
                return Err(Error::protocol(
                    "URL IPv6 host must be enclosed in brackets",
                ));
            }
            (host, parse_port(port)?)
        }
        None => (authority, default_port),
    };
    if host.is_empty() || contains_forbidden_authority_byte(host) {
        return Err(Error::protocol("invalid URL host"));
    }
    Ok((host.to_ascii_lowercase(), port))
}

impl Url {
    /// Parse an absolute URL.
    pub fn parse(s: &str) -> Result<Self> {
        let (scheme, rest) = s
            .split_once("://")
            .ok_or_else(|| Error::protocol("URL missing scheme://"))?;
        let scheme = scheme.to_ascii_lowercase();
        if scheme != "http" && scheme != "https" {
            return Err(Error::protocol(format!("unsupported scheme: {scheme}")));
        }
        // Fragments are not transmitted in HTTP request targets.
        let rest = rest.split_once('#').map_or(rest, |(before, _)| before);
        let (authority, pathq) = match rest.find(['/', '?']) {
            Some(index) => (&rest[..index], &rest[index..]),
            None => (rest, ""),
        };
        let (userinfo, hostport) = match authority.rsplit_once('@') {
            Some((u, hp)) => (Some(u.to_string()), hp),
            None => (None, authority),
        };
        let default_port = if scheme == "https" { 443 } else { 80 };
        let (host, port) = parse_host_and_port(hostport, default_port)?;
        let path_and_query = if pathq.is_empty() {
            PathAndQuery::from_static("/")
        } else if pathq.starts_with('?') {
            let mut origin_form = String::with_capacity(pathq.len() + 1);
            origin_form.push('/');
            origin_form.push_str(pathq);
            PathAndQuery::from_bytes(origin_form.as_bytes())?
        } else {
            PathAndQuery::from_bytes(pathq.as_bytes())?
        };
        Ok(Self {
            scheme,
            host,
            port,
            path_and_query,
            userinfo,
        })
    }

    /// The authority (`host:port`).
    pub fn authority(&self) -> String {
        let bracketed = self.host.contains(':');
        let mut a = String::with_capacity(self.host.len() + 6 + usize::from(bracketed) * 2);
        if bracketed {
            a.push('[');
        }
        a.push_str(&self.host);
        if bracketed {
            a.push(']');
        }
        a.push(':');
        a.push_str(&self.port.to_string());
        a
    }
}

impl fmt::Display for Url {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}://{}", self.scheme, self.authority())?;
        f.write_str(self.path_and_query.as_str())
    }
}

impl core::str::FromStr for Url {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_url() {
        let u = Url::parse("http://example.com:8080/a/b?q=1").unwrap();
        assert_eq!(u.scheme, "http");
        assert_eq!(u.host, "example.com");
        assert_eq!(u.port, 8080);
        assert_eq!(u.path_and_query.as_str(), "/a/b?q=1");
    }

    #[test]
    fn default_ports() {
        assert_eq!(Url::parse("http://example.com/x").unwrap().port, 80);
        assert_eq!(Url::parse("https://example.com/x").unwrap().port, 443);
    }

    #[test]
    fn parses_bracketed_ipv6_and_normalizes_query_only_url() {
        let ipv6 = Url::parse("http://[::1]:8080/status").unwrap();
        assert_eq!(ipv6.host, "::1");
        assert_eq!(ipv6.port, 8080);
        assert_eq!(ipv6.authority(), "[::1]:8080");

        let query_only = Url::parse("https://example.com?active=true#local").unwrap();
        assert_eq!(query_only.path_and_query.as_str(), "/?active=true");
    }

    #[test]
    fn rejects_ambiguous_or_invalid_authority() {
        for url in [
            "http://example.com:",
            "http://example.com:not-a-port",
            "http://example.com:0",
            "http://example.com:65536",
            "http://::1/",
            "http://[::1/",
            "http://[::1]suffix/",
            "http://example.com\r\nInjected: value/",
        ] {
            assert!(Url::parse(url).is_err(), "must reject {url:?}");
        }
    }

    #[test]
    fn rejects_bad_scheme() {
        assert!(Url::parse("ftp://example.com/x").is_err());
    }
}
