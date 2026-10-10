use alloc::{sync::Arc, vec::Vec};
use core::marker::PhantomData;

use pki_types::PrivateKeyDer;
use rustls::sign::{Signer, SigningKey};
use rustls::{Error, SignatureScheme};
use signature::{RandomizedSigner, SignatureEncoding};

mod ecdsa;
mod eddsa;
mod rsa;

#[derive(Debug)]
struct GenericRandomizedSigner<S, T>
where
    S: SignatureEncoding,
    T: RandomizedSigner<S>,
{
    marker: PhantomData<S>,
    key: Arc<T>,
    scheme: SignatureScheme,
}

impl<S, T> Signer for GenericRandomizedSigner<S, T>
where
    S: SignatureEncoding + Send + Sync + core::fmt::Debug,
    T: RandomizedSigner<S> + Send + Sync + core::fmt::Debug,
{
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        self.key
            .try_sign_with_rng(&mut rand_core::OsRng, message)
            .map(|signature: S| signature.to_vec())
            .map_err(|_| Error::General("signing failed".into()))
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

#[derive(Debug)]
struct GenericSigner<S, T>
where
    S: SignatureEncoding,
    T: signature::Signer<S>,
{
    marker: PhantomData<S>,
    key: Arc<T>,
    scheme: SignatureScheme,
}

impl<S, T> Signer for GenericSigner<S, T>
where
    S: SignatureEncoding + Send + Sync + core::fmt::Debug,
    T: signature::Signer<S> + Send + Sync + core::fmt::Debug,
{
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        self.key
            .try_sign(message)
            .map(|signature: S| signature.to_vec())
            .map_err(|_| Error::General("signing failed".into()))
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

/// Decode a supported unencrypted DER private key.
pub fn any_supported_type(der: &PrivateKeyDer<'_>) -> Result<Arc<dyn SigningKey>, Error> {
    rsa::RsaSigningKey::try_from(der)
        .map(|key| Arc::new(key) as Arc<dyn SigningKey>)
        .or_else(|_| {
            ecdsa::EcdsaSigningKeyP256::try_from(der)
                .map(|key| Arc::new(key) as Arc<dyn SigningKey>)
        })
        .or_else(|_| {
            ecdsa::EcdsaSigningKeyP384::try_from(der)
                .map(|key| Arc::new(key) as Arc<dyn SigningKey>)
        })
        .or_else(|_| {
            eddsa::Ed25519SigningKey::try_from(der).map(|key| Arc::new(key) as Arc<dyn SigningKey>)
        })
        .map_err(|_| Error::General("unsupported or malformed private key".into()))
}
