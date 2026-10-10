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

impl SecureRandom for Provider {
    fn fill(&self, bytes: &mut [u8]) -> Result<(), GetRandomFailed> {
        use rand_core::RngCore;

        rand_core::OsRng
            .try_fill_bytes(bytes)
            .map_err(|_| GetRandomFailed)
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

pub const TLS13_AES_128_GCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
            hash_provider: hash::SHA256,
            confidentiality_limit: 1 << 24,
        },
        hkdf_provider: &rustls::crypto::tls13::HkdfUsingHmac(hmac::SHA256),
        aead_alg: &aead::gcm::Tls13Aes128Gcm,
        quic: None,
    });

pub const TLS13_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_AES_256_GCM_SHA384,
            hash_provider: hash::SHA384,
            confidentiality_limit: 1 << 24,
        },
        hkdf_provider: &rustls::crypto::tls13::HkdfUsingHmac(hmac::SHA384),
        aead_alg: &aead::gcm::Tls13Aes256Gcm,
        quic: None,
    });

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
const TLS12_RSA_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PKCS1_SHA256,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA512,
];

#[cfg(feature = "tls12")]
macro_rules! tls12_suite {
    ($name:ident, $hash:expr, $hmac:expr, $schemes:expr, $aead:expr, $limit:expr) => {
        pub const $name: SupportedCipherSuite =
            SupportedCipherSuite::Tls12(&rustls::Tls12CipherSuite {
                common: CipherSuiteCommon {
                    suite: CipherSuite::$name,
                    hash_provider: $hash,
                    confidentiality_limit: $limit,
                },
                kx: rustls::crypto::KeyExchangeAlgorithm::ECDHE,
                sign: $schemes,
                aead_alg: $aead,
                prf_provider: &rustls::crypto::tls12::PrfUsingHmac($hmac),
            });
    };
}

#[cfg(feature = "tls12")]
tls12_suite!(
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    hash::SHA256,
    hmac::SHA256,
    TLS12_ECDSA_SCHEMES,
    &aead::gcm::Tls12Aes128Gcm,
    1 << 24
);
#[cfg(feature = "tls12")]
tls12_suite!(
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    hash::SHA384,
    hmac::SHA384,
    TLS12_ECDSA_SCHEMES,
    &aead::gcm::Tls12Aes256Gcm,
    1 << 24
);
#[cfg(feature = "tls12")]
tls12_suite!(
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    hash::SHA256,
    hmac::SHA256,
    TLS12_ECDSA_SCHEMES,
    &aead::chacha20::Chacha20Poly1305,
    u64::MAX
);
#[cfg(feature = "tls12")]
tls12_suite!(
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    hash::SHA256,
    hmac::SHA256,
    TLS12_RSA_SCHEMES,
    &aead::gcm::Tls12Aes128Gcm,
    1 << 24
);
#[cfg(feature = "tls12")]
tls12_suite!(
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    hash::SHA384,
    hmac::SHA384,
    TLS12_RSA_SCHEMES,
    &aead::gcm::Tls12Aes256Gcm,
    1 << 24
);
#[cfg(feature = "tls12")]
tls12_suite!(
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    hash::SHA256,
    hmac::SHA256,
    TLS12_RSA_SCHEMES,
    &aead::chacha20::Chacha20Poly1305,
    u64::MAX
);

pub static ALL_CIPHER_SUITES: &[SupportedCipherSuite] = &[
    TLS13_AES_128_GCM_SHA256,
    TLS13_AES_256_GCM_SHA384,
    TLS13_CHACHA20_POLY1305_SHA256,
    #[cfg(feature = "tls12")]
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    #[cfg(feature = "tls12")]
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    #[cfg(feature = "tls12")]
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    #[cfg(feature = "tls12")]
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    #[cfg(feature = "tls12")]
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    #[cfg(feature = "tls12")]
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
];
