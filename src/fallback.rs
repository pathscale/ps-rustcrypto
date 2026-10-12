//! The RSA fallback chain verifier, for the second connection only.
//!
//! The first connection to a host is ECC-only (`policy::EccOnlyVerifier`). When
//! that ends in our RSA refusal (alert 43) or the server rejecting the
//! ECC-only hello (alert 40), the caller may open a new connection with this
//! verifier. It keeps every native root, RSA ones included, and verifies RSA
//! certificate signatures with PKCS#1 v1.5 and the server CertificateVerify
//! with RSA-PSS, through `rsa-handshake`. Keys stay at 2048 to 8192 bits with
//! exponent 65537.
//!
//! RSA roots live only in this store; the ECC-only store never sees them.

use alloc::sync::Arc;

use rustls::client::{VerifierBuilderError, WebPkiServerVerifier};
use rustls::{AlertDescription, Error, RootCertStore};

/// A webpki verifier over every root, using `provider_with_rsa_pss()`.
pub fn rsa_fallback_verifier(
    roots: RootCertStore,
) -> Result<Arc<WebPkiServerVerifier>, VerifierBuilderError> {
    WebPkiServerVerifier::builder_with_provider(
        Arc::new(roots),
        Arc::new(crate::provider_with_rsa_pss()),
    )
    .build()
}

/// Whether an ECC-only handshake error should be retried with the fallback:
/// our own RSA refusal, or the server answering handshake_failure.
pub fn wants_rsa_fallback(error: &Error) -> bool {
    crate::policy::is_rsa_refusal(error)
        || matches!(
            error,
            Error::AlertReceived(AlertDescription::HandshakeFailure)
        )
}
