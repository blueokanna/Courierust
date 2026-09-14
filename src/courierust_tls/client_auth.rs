//! Client authentication (mTLS) policy for the TLS 1.3 server.
//!
//! A server that authenticates its peers asks for a certificate with a
//! `CertificateRequest` (RFC 8446 §4.4.2) and validates what comes back
//! against roots *it* chose. Both halves are policy, so they live in one
//! type: the roots and whether a client without a certificate may still
//! connect. The handshake code reads the decision, it does not make it.

use crate::courierust_tls::RootStore;

/// How a server authenticates connecting clients.
///
/// ```no_run
/// # use courierust::courierust_tls::{ClientAuth, RootStore};
/// let mut roots = RootStore::new();
/// roots.add_pem_file("client-ca.pem")?;
/// // Require a certificate: an anonymous client fails the handshake with
/// // `certificate_required` (RFC 8446 §6.2).
/// let required = ClientAuth::required(roots);
/// # Ok::<(), courierust::courierust_tls::TlsError>(())
/// ```
#[derive(Clone)]
pub struct ClientAuth {
    roots: RootStore,
    required: bool,
}

impl ClientAuth {
    /// Ask every client for a certificate and refuse those without one.
    pub fn required(roots: RootStore) -> Self {
        Self {
            roots,
            required: true,
        }
    }

    /// Ask every client for a certificate; a client that presents none is
    /// treated as anonymous instead of being refused. Useful when the
    /// certificate is an *additional* credential (audit, rate limits)
    /// rather than the gate.
    pub fn optional(roots: RootStore) -> Self {
        Self {
            roots,
            required: false,
        }
    }

    /// The roots a client certificate must chain to.
    pub fn roots(&self) -> &RootStore {
        &self.roots
    }

    /// Whether a client without a certificate is refused.
    pub fn is_required(&self) -> bool {
        self.required
    }
}

impl core::fmt::Debug for ClientAuth {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ClientAuth")
            .field("roots", &self.roots.len())
            .field("required", &self.required)
            .finish()
    }
}
