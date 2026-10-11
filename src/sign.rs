use alloc::{sync::Arc, vec::Vec};
use core::marker::PhantomData;

use pki_types::PrivateKeyDer;
use rustls::sign::{Signer, SigningKey};
use rustls::{Error, SignatureScheme};
use signature::SignatureEncoding;

mod ecdsa;
mod eddsa;

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

/// Decode a supported unencrypted DER private key (ECDSA P-256/P-384 or Ed25519).
pub fn any_supported_type(der: &PrivateKeyDer<'_>) -> Result<Arc<dyn SigningKey>, Error> {
    ecdsa::EcdsaSigningKeyP256::try_from(der)
        .map(|key| Arc::new(key) as Arc<dyn SigningKey>)
        .or_else(|_| {
            ecdsa::EcdsaSigningKeyP384::try_from(der)
                .map(|key| Arc::new(key) as Arc<dyn SigningKey>)
        })
        .or_else(|_| {
            eddsa::Ed25519SigningKey::try_from(der).map(|key| Arc::new(key) as Arc<dyn SigningKey>)
        })
        .map_err(|_| Error::General("unsupported or malformed private key".into()))
}
