use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::marker::PhantomData;

use pkcs8::{DecodePrivateKey, EncodePublicKey};
use pki_types::{PrivateKeyDer, SubjectPublicKeyInfoDer};
use rustls::sign::{Signer, SigningKey};
use rustls::{Error, SignatureAlgorithm, SignatureScheme};

#[derive(Debug)]
pub(super) struct Ed25519SigningKey {
    key: Arc<ed25519_dalek::SigningKey>,
    spki: Vec<u8>,
}

impl TryFrom<&PrivateKeyDer<'_>> for Ed25519SigningKey {
    type Error = Error;

    fn try_from(value: &PrivateKeyDer<'_>) -> Result<Self, Error> {
        let PrivateKeyDer::Pkcs8(der) = value else {
            return Err(Error::General("Ed25519 requires a PKCS#8 key".into()));
        };
        let key = ed25519_dalek::SigningKey::from_pkcs8_der(der.secret_pkcs8_der())
            .map_err(|_| Error::General("invalid Ed25519 PKCS#8 key".into()))?;
        let spki = key
            .verifying_key()
            .to_public_key_der()
            .map_err(|_| Error::General("Ed25519 public key encoding failed".into()))?
            .as_bytes()
            .to_vec();
        Ok(Self {
            key: Arc::new(key),
            spki,
        })
    }
}

impl SigningKey for Ed25519SigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered.contains(&SignatureScheme::ED25519).then(|| {
            Box::new(super::GenericSigner::<ed25519_dalek::Signature, _> {
                marker: PhantomData,
                key: Arc::clone(&self.key),
                scheme: SignatureScheme::ED25519,
            }) as Box<dyn Signer>
        })
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(SubjectPublicKeyInfoDer::from(self.spki.as_slice()))
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ED25519
    }
}
