use digest::Digest;
use pki_types::{alg_id, AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm};
use signature::hazmat::PrehashVerifier;

macro_rules! impl_ecdsa {
    ($name:ident, $verifier:ident, $public:expr, $signature_id:expr, $key:ty, $signature:ty, $hash:ty) => {
        #[derive(Debug)]
        struct $verifier;

        impl SignatureVerificationAlgorithm for $verifier {
            fn public_key_alg_id(&self) -> AlgorithmIdentifier {
                $public
            }

            fn signature_alg_id(&self) -> AlgorithmIdentifier {
                $signature_id
            }

            fn verify_signature(
                &self,
                public_key: &[u8],
                message: &[u8],
                signature: &[u8],
            ) -> Result<(), InvalidSignature> {
                let signature =
                    <$signature>::from_der(signature).map_err(|_| super::invalid_signature())?;
                let key =
                    <$key>::from_sec1_bytes(public_key).map_err(|_| super::invalid_signature())?;
                let digest = <$hash>::digest(message);
                key.verify_prehash(&digest, &signature)
                    .map_err(|_| super::invalid_signature())
            }
        }

        pub const $name: &dyn SignatureVerificationAlgorithm = super::algorithm(&$verifier);
    };
}

impl_ecdsa!(
    ECDSA_P256_SHA256,
    EcdsaVerifierP256Sha256,
    alg_id::ECDSA_P256,
    alg_id::ECDSA_SHA256,
    p256::ecdsa::VerifyingKey,
    p256::ecdsa::Signature,
    sha2::Sha256
);
impl_ecdsa!(
    ECDSA_P256_SHA384,
    EcdsaVerifierP256Sha384,
    alg_id::ECDSA_P256,
    alg_id::ECDSA_SHA384,
    p256::ecdsa::VerifyingKey,
    p256::ecdsa::Signature,
    sha2::Sha384
);
impl_ecdsa!(
    ECDSA_P384_SHA256,
    EcdsaVerifierP384Sha256,
    alg_id::ECDSA_P384,
    alg_id::ECDSA_SHA256,
    p384::ecdsa::VerifyingKey,
    p384::ecdsa::Signature,
    sha2::Sha256
);
impl_ecdsa!(
    ECDSA_P384_SHA384,
    EcdsaVerifierP384Sha384,
    alg_id::ECDSA_P384,
    alg_id::ECDSA_SHA384,
    p384::ecdsa::VerifyingKey,
    p384::ecdsa::Signature,
    sha2::Sha384
);
