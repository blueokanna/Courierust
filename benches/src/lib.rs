//! Shared benchmark helpers.
//!
//! Compiled once into the bench package's library target so every bench
//! binary reuses the same timing/sampling code instead of owning a copy.

pub mod metrics;

/// A `reqwest` client builder that never routes through an HTTP proxy.
///
/// Every comparison in this workspace talks to a server the same process
/// just bound on loopback, and `reqwest` honours `HTTP_PROXY` /
/// `HTTPS_PROXY` from the environment. On a machine with a local proxy
/// configured — routine for developers, and not visible in the code — the
/// request is then sent *to the proxy*: for `http://` that still reaches the
/// origin through the proxy's forwarding, which is why only the
/// prior-knowledge `h2c` cases fail (`PRI * HTTP/2.0` is not a request a
/// plain HTTP proxy can serve), and the failure names neither implementation.
/// `no_proxy()` is the difference between "the crate has an interop bug" and
/// "the benchmark was measured against a proxy".
pub fn reqwest_loopback() -> reqwest::ClientBuilder {
    reqwest::Client::builder().no_proxy()
}

/// The blocking counterpart of [`reqwest_loopback`].
pub fn reqwest_loopback_blocking() -> reqwest::blocking::ClientBuilder {
    reqwest::blocking::Client::builder().no_proxy()
}
