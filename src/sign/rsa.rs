use alloc::{boxed::Box, sync::Arc, vec::Vec};

use pkcs8::{DecodePrivateKey, EncodePublicKey};
use pki_types::{PrivateKeyDer, SubjectPublicKeyInfoDer};
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;
use rustls::sign::{Signer, SigningKey};
use rustls::{Error, SignatureAlgorithm, SignatureScheme};
use sha2::{Sha256, Sha384, Sha512};

const ALL_RSA_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PKCS1_SHA512,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA256,
];

#[derive(Debug)]
pub(super) struct RsaSigningKey {
    key: Arc<RsaPrivateKey>,
    spki: Vec<u8>,
}

impl TryFrom<&PrivateKeyDer<'_>> for RsaSigningKey {
    type Error = Error;

    fn try_from(value: &PrivateKeyDer<'_>) -> Result<Self, Error> {
        let key = match value {
            PrivateKeyDer::Pkcs8(der) => RsaPrivateKey::from_pkcs8_der(der.secret_pkcs8_der())
                .map_err(|_| Error::General("invalid RSA PKCS#8 key".into()))?,
            PrivateKeyDer::Pkcs1(der) => RsaPrivateKey::from_pkcs1_der(der.secret_pkcs1_der())
                .map_err(|_| Error::General("invalid RSA PKCS#1 key".into()))?,
            _ => return Err(Error::General("unsupported RSA key encoding".into())),
        };
        if !(2048..=8192).contains(&key.n().bits()) {
            return Err(Error::General("unsupported RSA modulus size".into()));
        }
        let spki = key
            .to_public_key()
            .to_public_key_der()
            .map_err(|_| Error::General("RSA public key encoding failed".into()))?
            .as_bytes()
            .to_vec();
        Ok(Self {
            key: Arc::new(key),
            spki,
        })
    }
}

impl SigningKey for RsaSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        let scheme = ALL_RSA_SCHEMES
            .iter()
            .copied()
            .find(|scheme| offered.contains(scheme))?;
        macro_rules! signer {
            ($key:ty) => {
                Some(Box::new(super::GenericRandomizedSigner {
                    marker: Default::default(),
                    key: Arc::new(<$key>::new(self.key.as_ref().clone())),
                    scheme,
                }) as Box<dyn Signer>)
            };
        }
        match scheme {
            SignatureScheme::RSA_PSS_SHA512 => signer!(rsa::pss::BlindedSigningKey<Sha512>),
            SignatureScheme::RSA_PSS_SHA384 => signer!(rsa::pss::BlindedSigningKey<Sha384>),
            SignatureScheme::RSA_PSS_SHA256 => signer!(rsa::pss::BlindedSigningKey<Sha256>),
            SignatureScheme::RSA_PKCS1_SHA512 => signer!(rsa::pkcs1v15::SigningKey<Sha512>),
            SignatureScheme::RSA_PKCS1_SHA384 => signer!(rsa::pkcs1v15::SigningKey<Sha384>),
            SignatureScheme::RSA_PKCS1_SHA256 => signer!(rsa::pkcs1v15::SigningKey<Sha256>),
            _ => None,
        }
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(SubjectPublicKeyInfoDer::from(self.spki.as_slice()))
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::RSA
    }
}
