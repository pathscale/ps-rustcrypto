#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::sync::Arc;

use rustls::crypto::{
    CipherSuiteCommon, CryptoProvider, GetRandomFailed, KeyProvider, SecureRandom,
};
use rustls::{CipherSuite, SupportedCipherSuite, Tls13CipherSuite};

#[cfg(feature = "tls12")]
use rustls::SignatureScheme;

mod aead;
mod hash;
mod hmac;
mod kx;
#[cfg(feature = "std")]
pub mod policy;
pub mod sign;
mod verify;

#[derive(Debug)]
pub struct Provider;

/// Construct a provider without changing process-global state.
pub fn provider() -> CryptoProvider {
    CryptoProvider {
        cipher_suites: ALL_CIPHER_SUITES.to_vec(),
        kx_groups: kx::ALL_KX_GROUPS.to_vec(),
        signature_verification_algorithms: verify::ALGORITHMS,
        secure_random: &Provider,
        key_provider: &Provider,
    }
}

/// `provider()` that also accepts RSA-PSS server handshake signatures.
///
/// Only the CertificateVerify can be RSA; chains signed with RSA PKCS#1 v1.5
/// are still refused.
#[cfg(feature = "rsa-pss")]
pub fn provider_with_rsa_pss() -> CryptoProvider {
    CryptoProvider {
        signature_verification_algorithms: verify::ALGORITHMS_WITH_RSA_PSS,
        ..provider()
    }
}

impl SecureRandom for Provider {
    fn fill(&self, bytes: &mut [u8]) -> Result<(), GetRandomFailed> {
        getrandom::fill(bytes).map_err(|_| GetRandomFailed)
    }
}

impl KeyProvider for Provider {
    fn load_private_key(
        &self,
        key_der: pki_types::PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn rustls::sign::SigningKey>, rustls::Error> {
        sign::any_supported_type(&key_der)
    }
}

pub const TLS13_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
            hash_provider: hash::SHA256,
            confidentiality_limit: u64::MAX,
        },
        hkdf_provider: &rustls::crypto::tls13::HkdfUsingHmac(hmac::SHA256),
        aead_alg: &aead::chacha20::Chacha20Poly1305,
        quic: None,
    });

#[cfg(feature = "tls12")]
const TLS12_ECDSA_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::ECDSA_NISTP256_SHA256,
    SignatureScheme::ECDSA_NISTP384_SHA384,
    SignatureScheme::ED25519,
];

#[cfg(feature = "tls12")]
pub const TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&rustls::Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            hash_provider: hash::SHA256,
            confidentiality_limit: u64::MAX,
        },
        kx: rustls::crypto::KeyExchangeAlgorithm::ECDHE,
        sign: TLS12_ECDSA_SCHEMES,
        aead_alg: &aead::chacha20::Chacha20Poly1305,
        prf_provider: &rustls::crypto::tls12::PrfUsingHmac(hmac::SHA256),
    });

/// ChaCha20-Poly1305 only: no AES suites and no RSA authentication.
pub static ALL_CIPHER_SUITES: &[SupportedCipherSuite] = &[
    TLS13_CHACHA20_POLY1305_SHA256,
    #[cfg(feature = "tls12")]
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
];
