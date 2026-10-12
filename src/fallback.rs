//! The RSA fallback chain verifier, for the second connection only.
//!
//! The first connection to a host is ECC-only (`policy::EccOnlyVerifier`). When
//! that ends in our RSA refusal (alert 43) or the server rejecting the
//! ECC-only hello (alert 40, or a non-handshake record in its place), the caller may open a new connection with this
//! verifier. It keeps every native root, RSA ones included, and verifies RSA
//! certificate signatures with PKCS#1 v1.5 and the server CertificateVerify
//! with RSA-PSS, through `legacy-bullshit`. Keys stay at 2048 to 8192 bits with
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

/// The RSA fallback verifier over roots, with CT on chains that also
/// validate against public_roots, the publicly trusted subset.
pub fn rsa_fallback_ct_verifier(
    roots: RootCertStore,
    public_roots: RootCertStore,
) -> Result<Arc<crate::policy::ct::CtVerifier>, VerifierBuilderError> {
    use crate::policy::ct::CtVerifier;
    let inner = rsa_fallback_verifier(roots)?;
    if public_roots.is_empty() {
        return Ok(CtVerifier::without_public_roots(inner));
    }
    let public = rsa_fallback_verifier(public_roots)?;
    Ok(CtVerifier::public_only(inner, public))
}

/// Whether an ECC-only handshake error should be retried with the fallback:
/// our own RSA refusal, the server answering handshake_failure, or the server
/// answering the hello with a record that is not a handshake message.
///
/// The last one is how some CDNs (Fastly, seen on abs.twimg.com) reject a
/// TLS 1.3 hello whose signature schemes they cannot serve with an RSA-only
/// certificate: instead of alert 40 they send an ApplicationData record where
/// the ServerHello belongs. OpenSSL limited to the same schemes fails there
/// the same way, so it is the server, not the record loop.
pub fn wants_rsa_fallback(error: &Error) -> bool {
    crate::policy::is_rsa_refusal(error)
        || matches!(
            error,
            Error::AlertReceived(AlertDescription::HandshakeFailure)
        )
        || is_non_handshake_reply(error)
}

/// A plaintext ApplicationData record where only a handshake message may be.
///
/// rustls reports this only before the handshake keys are in place: once
/// records are encrypted their outer type is always ApplicationData and is
/// checked after decryption.
fn is_non_handshake_reply(error: &Error) -> bool {
    matches!(
        error,
        Error::InappropriateMessage { expect_types, got_type }
            if *got_type == rustls::ContentType::ApplicationData
                && expect_types.as_slice() == [rustls::ContentType::Handshake]
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use rustls::ContentType;

    #[test]
    fn application_data_instead_of_server_hello_wants_fallback() {
        let error = Error::InappropriateMessage {
            expect_types: vec![ContentType::Handshake],
            got_type: ContentType::ApplicationData,
        };
        assert!(wants_rsa_fallback(&error));
    }

    #[test]
    fn other_unexpected_records_do_not() {
        let error = Error::InappropriateMessage {
            expect_types: vec![ContentType::Handshake],
            got_type: ContentType::Alert,
        };
        assert!(!wants_rsa_fallback(&error));
        assert!(!wants_rsa_fallback(&Error::AlertReceived(
            AlertDescription::UnexpectedMessage
        )));
    }
}
