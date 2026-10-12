use pki_types::{alg_id, AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm};
use rsa_handshake::{Hash, RsaPublicKey};

macro_rules! impl_rsa {
    ($name:ident, $verifier:ident, $signature_id:expr, $hash:expr, $verify:ident) => {
        #[derive(Debug)]
        struct $verifier;

        impl SignatureVerificationAlgorithm for $verifier {
            fn public_key_alg_id(&self) -> AlgorithmIdentifier {
                alg_id::RSA_ENCRYPTION
            }

            fn signature_alg_id(&self) -> AlgorithmIdentifier {
                $signature_id
            }

            // `public_key` is the PKCS#1 RSAPublicKey from the SPKI bit string.
            fn verify_signature(
                &self,
                public_key: &[u8],
                message: &[u8],
                signature: &[u8],
            ) -> Result<(), InvalidSignature> {
                let key =
                    RsaPublicKey::from_der(public_key).map_err(|_| super::invalid_signature())?;
                key.$verify($hash, message, signature)
                    .map_err(|_| super::invalid_signature())
            }
        }

        pub const $name: &dyn SignatureVerificationAlgorithm = super::algorithm(&$verifier);
    };
}

impl_rsa!(
    RSA_PSS_SHA256,
    RsaPssSha256,
    alg_id::RSA_PSS_SHA256,
    Hash::Sha256,
    verify_pss
);
impl_rsa!(
    RSA_PSS_SHA384,
    RsaPssSha384,
    alg_id::RSA_PSS_SHA384,
    Hash::Sha384,
    verify_pss
);
impl_rsa!(
    RSA_PSS_SHA512,
    RsaPssSha512,
    alg_id::RSA_PSS_SHA512,
    Hash::Sha512,
    verify_pss
);

// Certificate signatures only: never mapped to a TLS signature scheme.
impl_rsa!(
    RSA_PKCS1_SHA256,
    RsaPkcs1Sha256,
    alg_id::RSA_PKCS1_SHA256,
    Hash::Sha256,
    verify_pkcs1v15
);
impl_rsa!(
    RSA_PKCS1_SHA384,
    RsaPkcs1Sha384,
    alg_id::RSA_PKCS1_SHA384,
    Hash::Sha384,
    verify_pkcs1v15
);
impl_rsa!(
    RSA_PKCS1_SHA512,
    RsaPkcs1Sha512,
    alg_id::RSA_PKCS1_SHA512,
    Hash::Sha512,
    verify_pkcs1v15
);
