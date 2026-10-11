use pki_types::{InvalidSignature, SignatureVerificationAlgorithm};
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::SignatureScheme;

use self::ecdsa::{ECDSA_P256_SHA256, ECDSA_P256_SHA384, ECDSA_P384_SHA256, ECDSA_P384_SHA384};
use self::eddsa::ED25519;

mod ecdsa;
mod eddsa;

/// ECDSA and Ed25519 only: servers and chains that need RSA are refused.
pub static ALGORITHMS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[
        ECDSA_P256_SHA256,
        ECDSA_P256_SHA384,
        ECDSA_P384_SHA256,
        ECDSA_P384_SHA384,
        ED25519,
    ],
    mapping: &[
        (
            SignatureScheme::ECDSA_NISTP256_SHA256,
            &[ECDSA_P256_SHA256, ECDSA_P384_SHA256],
        ),
        (
            SignatureScheme::ECDSA_NISTP384_SHA384,
            &[ECDSA_P384_SHA384, ECDSA_P256_SHA384],
        ),
        (SignatureScheme::ED25519, &[ED25519]),
    ],
};

fn invalid_signature() -> InvalidSignature {
    InvalidSignature
}

const fn algorithm(
    value: &'static dyn SignatureVerificationAlgorithm,
) -> &'static dyn SignatureVerificationAlgorithm {
    value
}
