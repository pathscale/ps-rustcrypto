use alloc::boxed::Box;

use paste::paste;
use rand_core::RngCore;
use rustls::crypto::{ActiveKeyExchange, SharedSecret, SupportedKxGroup};
use rustls::{Error, NamedGroup, PeerMisbehaved};

fn entropy(bytes: &mut [u8]) -> Result<(), Error> {
    rand_core::OsRng
        .try_fill_bytes(bytes)
        .map_err(|_| Error::FailedToGetRandomBytes)
}

fn invalid_share() -> Error {
    PeerMisbehaved::InvalidKeyShare.into()
}

#[derive(Debug)]
struct X25519;

impl SupportedKxGroup for X25519 {
    fn name(&self) -> NamedGroup {
        NamedGroup::X25519
    }

    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let mut bytes = [0u8; 32];
        entropy(&mut bytes)?;
        let secret = x25519_dalek::StaticSecret::from(bytes);
        bytes.fill(0);
        let public = x25519_dalek::PublicKey::from(&secret);
        Ok(Box::new(X25519Exchange { secret, public }))
    }
}

struct X25519Exchange {
    secret: x25519_dalek::StaticSecret,
    public: x25519_dalek::PublicKey,
}

impl ActiveKeyExchange for X25519Exchange {
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
        let bytes: [u8; 32] = peer.try_into().map_err(|_| invalid_share())?;
        let secret = self
            .secret
            .diffie_hellman(&x25519_dalek::PublicKey::from(bytes));
        if !secret.was_contributory() {
            return Err(invalid_share());
        }
        Ok(secret.as_bytes().as_slice().into())
    }

    fn pub_key(&self) -> &[u8] {
        self.public.as_bytes()
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

macro_rules! impl_kx {
    ($name:ident, $group:expr, $curve:ident, $size:expr) => {
        paste! {
            #[derive(Debug)]
            struct $name;

            impl SupportedKxGroup for $name {
                fn name(&self) -> NamedGroup {
                    $group
                }

                fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
                    let mut bytes = [0u8; $size];
                    let secret = loop {
                        entropy(&mut bytes)?;
                        if let Ok(secret) = $curve::SecretKey::from_slice(&bytes) {
                            break secret;
                        }
                    };
                    bytes.fill(0);
                    let public = secret.public_key().to_sec1_bytes();
                    Ok(Box::new([<$name Exchange>] { secret, public }))
                }
            }

            struct [<$name Exchange>] {
                secret: $curve::SecretKey,
                public: Box<[u8]>,
            }

            impl ActiveKeyExchange for [<$name Exchange>] {
                fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
                    // TLS uses the uncompressed SEC1 representation.
                    if peer.len() != 1 + 2 * $size || peer.first() != Some(&4) {
                        return Err(invalid_share());
                    }
                    let public = $curve::PublicKey::from_sec1_bytes(peer)
                        .map_err(|_| invalid_share())?;
                    let secret = $curve::ecdh::diffie_hellman(
                        self.secret.to_nonzero_scalar(),
                        public.as_affine(),
                    );
                    Ok(secret.raw_secret_bytes().as_slice().into())
                }

                fn pub_key(&self) -> &[u8] {
                    &self.public
                }

                fn group(&self) -> NamedGroup {
                    $group
                }
            }
        }
    };
}

impl_kx!(P256, NamedGroup::secp256r1, p256, 32);
impl_kx!(P384, NamedGroup::secp384r1, p384, 48);

pub const ALL_KX_GROUPS: &[&dyn SupportedKxGroup] = &[&X25519, &P256, &P384];
