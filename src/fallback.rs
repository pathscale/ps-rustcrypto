//! RSA-capable certificate verifiers and caller-selected connection attempts.
//!
//! Choose the TLS configuration for the destination before connecting. For
//! destinations that require RSA, use `crate::provider_with_rsa_pss()` with the
//! appropriate verifier and trust roots. A handshake error cannot authorize a
//! switch from an ECC-only configuration to an RSA-capable configuration.

use alloc::sync::Arc;

use pki_types::ServerName;
use rustls::client::{VerifierBuilderError, WebPkiServerVerifier};
#[cfg(feature = "std")]
use rustls::ClientConnection;
use rustls::{ClientConfig, Error, RootCertStore};

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
/// validate against public_roots, the publicly trusted subset. Chains with
/// no issuer in public_roots skip CT; any other public_roots validation
/// error refuses the chain.
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

/// How many connections the caller authorizes for the selected TLS configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryPolicy {
    /// Allow only the initial connection.
    Never,
    /// Allow one fresh connection with the same configuration and server name.
    SameConfigOnce,
}

/// Connection attempts for one destination, using the TLS configuration and
/// retry policy the caller selected before the first handshake.
///
/// The caller owns the transport and decides when to use an authorized retry.
/// Stop on success or a TLS validation failure. Reuse this value for the
/// lifetime of the operation so the attempt limit applies across connections.
pub struct HandshakeAttempts {
    config: Arc<ClientConfig>,
    server_name: ServerName<'static>,
    remaining: u8,
}

impl HandshakeAttempts {
    pub fn new(
        config: Arc<ClientConfig>,
        server_name: ServerName<'static>,
        retry: RetryPolicy,
    ) -> Self {
        let remaining = match retry {
            RetryPolicy::Never => 1,
            RetryPolicy::SameConfigOnce => 2,
        };
        Self {
            config,
            server_name,
            remaining,
        }
    }

    /// Create the next connection. Each call consumes an attempt, including
    /// when rustls cannot create the connection. Returns `None` when exhausted.
    #[cfg(feature = "std")]
    pub fn next_attempt(&mut self) -> Option<Result<ClientConnection, Error>> {
        self.remaining = self.remaining.checked_sub(1)?;
        Some(ClientConnection::new(
            self.config.clone(),
            self.server_name.clone(),
        ))
    }
}

/// Legacy error classifier. Always returns `false`.
///
/// Even a local RSA refusal can be based on certificate input the verifier
/// has yet to authenticate. Select the TLS configuration from caller policy
/// before connecting.
#[deprecated(note = "select the TLS configuration and RetryPolicy before connecting")]
pub fn wants_rsa_fallback(_error: &Error) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use rustls::crypto::CryptoProvider;
    use rustls::server::Acceptor;
    use rustls::{version::TLS13, AlertDescription, ContentType, SignatureScheme};

    fn attempts(provider: CryptoProvider, retry: RetryPolicy) -> HandshakeAttempts {
        let roots = RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        let config = ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        HandshakeAttempts::new(
            Arc::new(config),
            ServerName::try_from("localhost").unwrap(),
            retry,
        )
    }

    fn offers_rsa(client: &mut ClientConnection) -> bool {
        let mut bytes = Vec::new();
        while client.wants_write() {
            client.write_tls(&mut bytes).unwrap();
        }
        let mut acceptor = Acceptor::default();
        acceptor.read_tls(&mut bytes.as_slice()).unwrap();
        let accepted = acceptor.accept().unwrap().unwrap();
        let hello = accepted.client_hello();
        assert_eq!(hello.server_name(), Some("localhost"));
        hello
            .signature_schemes()
            .contains(&SignatureScheme::RSA_PSS_SHA256)
    }

    #[test]
    #[allow(deprecated)]
    fn peer_failures_keep_the_ecc_config_and_spend_the_retry() {
        let cases: &[(&[u8], Error)] = &[
            (
                &[21, 3, 3, 0, 2, 2, 40],
                Error::AlertReceived(AlertDescription::HandshakeFailure),
            ),
            (
                &[23, 3, 3, 0, 1, 0],
                Error::InappropriateMessage {
                    expect_types: vec![ContentType::Handshake],
                    got_type: ContentType::ApplicationData,
                },
            ),
            (
                &[21, 3, 3, 0, 2, 2, 10],
                Error::AlertReceived(AlertDescription::UnexpectedMessage),
            ),
        ];
        for (record, expected) in cases {
            let mut attempts = attempts(crate::provider(), RetryPolicy::SameConfigOnce);
            for _ in 0..2 {
                let mut client = attempts.next_attempt().unwrap().unwrap();
                assert!(!offers_rsa(&mut client));
                let mut input = *record;
                client.read_tls(&mut input).unwrap();
                let error = client.process_new_packets().unwrap_err();
                assert_eq!(&error, expected);
                assert!(!wants_rsa_fallback(&error));
            }
            assert!(attempts.next_attempt().is_none());
            assert!(attempts.next_attempt().is_none());
        }
    }

    #[test]
    fn caller_can_select_rsa_before_handshake_without_enabling_retries() {
        let mut attempts = attempts(crate::provider_with_rsa_pss(), RetryPolicy::Never);
        assert!(offers_rsa(&mut attempts.next_attempt().unwrap().unwrap()));
        assert!(attempts.next_attempt().is_none());
    }
}
