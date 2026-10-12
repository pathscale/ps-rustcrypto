use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::marker::PhantomData;

use pkcs8::{DecodePrivateKey, EncodePublicKey};
use pki_types::{PrivateKeyDer, SubjectPublicKeyInfoDer};
use rustls::sign::SigningKey;
use rustls::{Error, SignatureAlgorithm, SignatureScheme};
use sec1::DecodeEcPrivateKey;

macro_rules! impl_ecdsa {
    ($name:ident, $scheme:expr, $secret_key:ty, $signing_key:ty, $signature:ty) => {
        #[derive(Debug)]
        pub(super) struct $name {
            key: Arc<$signing_key>,
            spki: Vec<u8>,
        }

        impl TryFrom<&PrivateKeyDer<'_>> for $name {
            type Error = Error;

            fn try_from(value: &PrivateKeyDer<'_>) -> Result<Self, Error> {
                let key = match value {
                    PrivateKeyDer::Pkcs8(der) => {
                        <$signing_key>::from_pkcs8_der(der.secret_pkcs8_der())
                            .map_err(|_| Error::General("invalid ECDSA PKCS#8 key".into()))?
                    }
                    PrivateKeyDer::Sec1(der) => {
                        let secret = <$secret_key as DecodeEcPrivateKey>::from_sec1_der(
                            der.secret_sec1_der(),
                        )
                        .map_err(|_| Error::General("invalid ECDSA SEC1 key".into()))?;
                        <$signing_key>::from(secret)
                    }
                    _ => return Err(Error::General("unsupported ECDSA key encoding".into())),
                };
                let spki = key
                    .verifying_key()
                    .to_public_key_der()
                    .map_err(|_| Error::General("ECDSA public key encoding failed".into()))?
                    .as_bytes()
                    .to_vec();
                Ok(Self {
                    key: Arc::new(key),
                    spki,
                })
            }
        }

        impl SigningKey for $name {
            fn choose_scheme(
                &self,
                offered: &[SignatureScheme],
            ) -> Option<Box<dyn rustls::sign::Signer>> {
                offered.contains(&$scheme).then(|| {
                    Box::new(super::GenericSigner::<$signature, _> {
                        marker: PhantomData,
                        key: Arc::clone(&self.key),
                        scheme: $scheme,
                    }) as Box<dyn rustls::sign::Signer>
                })
            }

            fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
                Some(SubjectPublicKeyInfoDer::from(self.spki.as_slice()))
            }

            fn algorithm(&self) -> SignatureAlgorithm {
                SignatureAlgorithm::ECDSA
            }
        }
    };
}

impl_ecdsa!(
    EcdsaSigningKeyP256,
    SignatureScheme::ECDSA_NISTP256_SHA256,
    p256::SecretKey,
    p256::ecdsa::SigningKey,
    p256::ecdsa::DerSignature
);
impl_ecdsa!(
    EcdsaSigningKeyP384,
    SignatureScheme::ECDSA_NISTP384_SHA384,
    p384::SecretKey,
    p384::ecdsa::SigningKey,
    p384::ecdsa::DerSignature
);
