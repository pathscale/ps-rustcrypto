use paste::paste;
use pki_types::{alg_id, AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm};
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::traits::PublicKeyParts;
use rsa::{pkcs1v15, pss, RsaPublicKey};
use sha2::{Sha256, Sha384, Sha512};
use signature::Verifier;

macro_rules! impl_rsa {
    ($name:ident, $signature_id:expr, $key:ty, $signature:ty) => {
        paste! {
            #[allow(non_camel_case_types)]
            #[derive(Debug)]
            struct [<RsaVerifier_ $name>];

            impl SignatureVerificationAlgorithm for [<RsaVerifier_ $name>] {
                fn public_key_alg_id(&self) -> AlgorithmIdentifier {
                    alg_id::RSA_ENCRYPTION
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
                    let key = RsaPublicKey::from_pkcs1_der(public_key)
                        .map_err(|_| super::invalid_signature())?;
                    if !(2048..=8192).contains(&key.n().bits()) {
                        return Err(super::invalid_signature());
                    }
                    let signature = <$signature>::try_from(signature)
                        .map_err(|_| super::invalid_signature())?;
                    <$key>::new(key)
                        .verify(message, &signature)
                        .map_err(|_| super::invalid_signature())
                }
            }

            pub const $name: &dyn SignatureVerificationAlgorithm =
                &[<RsaVerifier_ $name>];
        }
    };
}

impl_rsa!(
    RSA_PKCS1_SHA256,
    alg_id::RSA_PKCS1_SHA256,
    pkcs1v15::VerifyingKey<Sha256>,
    pkcs1v15::Signature
);
impl_rsa!(
    RSA_PKCS1_SHA384,
    alg_id::RSA_PKCS1_SHA384,
    pkcs1v15::VerifyingKey<Sha384>,
    pkcs1v15::Signature
);
impl_rsa!(
    RSA_PKCS1_SHA512,
    alg_id::RSA_PKCS1_SHA512,
    pkcs1v15::VerifyingKey<Sha512>,
    pkcs1v15::Signature
);
impl_rsa!(
    RSA_PSS_SHA256,
    alg_id::RSA_PSS_SHA256,
    pss::VerifyingKey<Sha256>,
    pss::Signature
);
impl_rsa!(
    RSA_PSS_SHA384,
    alg_id::RSA_PSS_SHA384,
    pss::VerifyingKey<Sha384>,
    pss::Signature
);
impl_rsa!(
    RSA_PSS_SHA512,
    alg_id::RSA_PSS_SHA512,
    pss::VerifyingKey<Sha512>,
    pss::Signature
);
