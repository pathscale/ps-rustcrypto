//! Policy guard: the provider never offers or accepts RSA, and never AES.
//! rustls builds the ClientHello signature_algorithms list from these
//! schemes, and TLS 1.3 applies that list to certificate chains too.

use rustls::{CipherSuite, SignatureScheme};

#[test]
fn verify_schemes_are_ecc_only() {
    let schemes = ps_rustcrypto::provider()
        .signature_verification_algorithms
        .supported_schemes();
    assert_eq!(
        schemes,
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
        ]
    );
}

#[test]
fn cipher_suites_are_chacha_only() {
    for suite in ps_rustcrypto::provider().cipher_suites {
        let name = format!("{:?}", suite.suite());
        assert!(
            name.contains("CHACHA20_POLY1305"),
            "unexpected suite {name}"
        );
        assert!(!name.contains("RSA"), "RSA suite {name}");
        assert_ne!(suite.suite(), CipherSuite::TLS13_AES_128_GCM_SHA256);
    }
}
