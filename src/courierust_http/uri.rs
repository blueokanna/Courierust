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
        // Absolute-form: must contain "://". Control characters are
        // rejected exactly as in origin-form (a CR/LF embedded in the
        // target could otherwise split the request line downstream).
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
        let (authority, pathq) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        let (userinfo, hostport) = match authority.rsplit_once('@') {
            Some((u, hp)) => (Some(u.to_string()), hp),
            None => (None, authority),
        };
        let (host, port) = match hostport.rsplit_once(':') {
            Some((h, p)) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => {
                (h.to_ascii_lowercase(), p.parse::<u16>().unwrap_or(0))
            }
            _ => (hostport.to_ascii_lowercase(), 0),
        };
        if host.is_empty() {
            return Err(Error::protocol("URL missing host"));
        }
        if port == 0 && !hostport.contains(':') {
            // no explicit port
        }
        let default_port = if scheme == "https" { 443 } else { 80 };
        let port = if port == 0 { default_port } else { port };
        let path_and_query = if pathq.is_empty() {
            PathAndQuery::from_static("/")
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
        let mut a = String::with_capacity(self.host.len() + 6);
        a.push_str(&self.host);
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
    fn rejects_bad_scheme() {
        assert!(Url::parse("ftp://example.com/x").is_err());
    }
}
