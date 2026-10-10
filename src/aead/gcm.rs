use alloc::boxed::Box;

use aead::AeadInPlace;
use crypto_common::{KeyInit, KeySizeUser};
use paste::paste;
use rustls::crypto::cipher::{
    self, AeadKey, InboundOpaqueMessage, InboundPlainMessage, MessageDecrypter, MessageEncrypter,
    OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload, Tls13AeadAlgorithm,
};
use rustls::{ConnectionTrafficSecrets, ContentType, ProtocolVersion};

use super::{DecryptBufferAdapter, EncryptBufferAdapter};

#[cfg(feature = "tls12")]
use rustls::crypto::cipher::{Iv, KeyBlockShape, Tls12AeadAlgorithm};

macro_rules! impl_gcm_tls13 {
    ($name:ident, $aead:ty, $traffic:ident) => {
        paste! {
            pub struct [<Tls13 $name>];

            impl Tls13AeadAlgorithm for [<Tls13 $name>] {
                fn encrypter(&self, key: AeadKey, iv: cipher::Iv) -> Box<dyn MessageEncrypter> {
                    Box::new([<Tls13Cipher $name>](
                        <$aead>::new_from_slice(key.as_ref())
                            .expect("rustls supplies the cipher's key length"),
                        iv,
                    ))
                }

                fn decrypter(&self, key: AeadKey, iv: cipher::Iv) -> Box<dyn MessageDecrypter> {
                    Box::new([<Tls13Cipher $name>](
                        <$aead>::new_from_slice(key.as_ref())
                            .expect("rustls supplies the cipher's key length"),
                        iv,
                    ))
                }

                fn key_len(&self) -> usize {
                    <$aead>::key_size()
                }

                fn extract_keys(
                    &self,
                    key: AeadKey,
                    iv: cipher::Iv,
                ) -> Result<ConnectionTrafficSecrets, cipher::UnsupportedOperationError> {
                    Ok(ConnectionTrafficSecrets::$traffic { key, iv })
                }
            }

            struct [<Tls13Cipher $name>]($aead, cipher::Iv);

            impl MessageEncrypter for [<Tls13Cipher $name>] {
                fn encrypt(
                    &mut self,
                    message: OutboundPlainMessage<'_>,
                    sequence: u64,
                ) -> Result<OutboundOpaqueMessage, rustls::Error> {
                    let total = self.encrypted_payload_len(message.payload.len());
                    let mut payload = PrefixedPayload::with_capacity(total);
                    let nonce = cipher::Nonce::new(&self.1, sequence).0;
                    let aad = cipher::make_tls13_aad(total);
                    payload.extend_from_chunks(&message.payload);
                    payload.extend_from_slice(&message.typ.to_array());
                    self.0
                        .encrypt_in_place(
                            &nonce.into(),
                            &aad,
                            &mut EncryptBufferAdapter(&mut payload),
                        )
                        .map_err(|_| rustls::Error::EncryptError)?;
                    Ok(OutboundOpaqueMessage::new(
                        ContentType::ApplicationData,
                        ProtocolVersion::TLSv1_2,
                        payload,
                    ))
                }

                fn encrypted_payload_len(&self, payload_len: usize) -> usize {
                    payload_len + 1 + 16
                }
            }

            impl MessageDecrypter for [<Tls13Cipher $name>] {
                fn decrypt<'a>(
                    &mut self,
                    mut message: InboundOpaqueMessage<'a>,
                    sequence: u64,
                ) -> Result<InboundPlainMessage<'a>, rustls::Error> {
                    let payload = &mut message.payload;
                    let nonce = cipher::Nonce::new(&self.1, sequence).0;
                    let aad = cipher::make_tls13_aad(payload.len());
                    self.0
                        .decrypt_in_place(
                            &nonce.into(),
                            &aad,
                            &mut DecryptBufferAdapter(payload),
                        )
                        .map_err(|_| rustls::Error::DecryptError)?;
                    message.into_tls13_unpadded_message()
                }
            }
        }
    };
}

impl_gcm_tls13!(Aes128Gcm, aes_gcm::Aes128Gcm, Aes128Gcm);
impl_gcm_tls13!(Aes256Gcm, aes_gcm::Aes256Gcm, Aes256Gcm);

#[cfg(feature = "tls12")]
fn gcm_iv(write_iv: &[u8], explicit: &[u8]) -> Iv {
    let mut iv = [0u8; 12];
    iv[..4].copy_from_slice(write_iv);
    iv[4..].copy_from_slice(explicit);
    Iv::new(iv)
}

#[cfg(feature = "tls12")]
macro_rules! impl_gcm_tls12 {
    ($name:ident, $aead:ty, $traffic:ident) => {
        paste! {
            pub struct [<Tls12 $name>];

            impl Tls12AeadAlgorithm for [<Tls12 $name>] {
                fn encrypter(
                    &self,
                    key: AeadKey,
                    write_iv: &[u8],
                    explicit: &[u8],
                ) -> Box<dyn MessageEncrypter> {
                    Box::new([<Tls12Cipher $name Encrypter>](
                        <$aead>::new_from_slice(key.as_ref())
                            .expect("rustls supplies the cipher's key length"),
                        gcm_iv(write_iv, explicit),
                    ))
                }

                fn decrypter(
                    &self,
                    key: AeadKey,
                    read_iv: &[u8],
                ) -> Box<dyn MessageDecrypter> {
                    Box::new([<Tls12Cipher $name Decrypter>](
                        <$aead>::new_from_slice(key.as_ref())
                            .expect("rustls supplies the cipher's key length"),
                        read_iv.try_into().expect("rustls supplies a four-byte GCM IV"),
                    ))
                }

                fn key_block_shape(&self) -> KeyBlockShape {
                    KeyBlockShape {
                        enc_key_len: <$aead>::key_size(),
                        fixed_iv_len: 4,
                        explicit_nonce_len: 8,
                    }
                }

                fn extract_keys(
                    &self,
                    key: AeadKey,
                    write_iv: &[u8],
                    explicit: &[u8],
                ) -> Result<ConnectionTrafficSecrets, cipher::UnsupportedOperationError> {
                    Ok(ConnectionTrafficSecrets::$traffic {
                        key,
                        iv: gcm_iv(write_iv, explicit),
                    })
                }
            }

            struct [<Tls12Cipher $name Encrypter>]($aead, Iv);

            impl MessageEncrypter for [<Tls12Cipher $name Encrypter>] {
                fn encrypt(
                    &mut self,
                    message: OutboundPlainMessage<'_>,
                    sequence: u64,
                ) -> Result<OutboundOpaqueMessage, rustls::Error> {
                    let mut payload = PrefixedPayload::with_capacity(
                        self.encrypted_payload_len(message.payload.len()),
                    );
                    let nonce = cipher::Nonce::new(&self.1, sequence).0;
                    let aad = cipher::make_tls12_aad(
                        sequence,
                        message.typ,
                        message.version,
                        message.payload.len(),
                    );
                    payload.extend_from_slice(&nonce[4..]);
                    payload.extend_from_chunks(&message.payload);
                    let tag = self.0
                        .encrypt_in_place_detached(
                            &nonce.into(),
                            &aad,
                            &mut payload.as_mut()[8..],
                        )
                        .map_err(|_| rustls::Error::EncryptError)?;
                    payload.extend_from_slice(&tag);
                    Ok(OutboundOpaqueMessage::new(
                        message.typ,
                        message.version,
                        payload,
                    ))
                }

                fn encrypted_payload_len(&self, payload_len: usize) -> usize {
                    payload_len + 24
                }
            }

            struct [<Tls12Cipher $name Decrypter>]($aead, [u8; 4]);

            impl MessageDecrypter for [<Tls12Cipher $name Decrypter>] {
                fn decrypt<'a>(
                    &mut self,
                    mut message: InboundOpaqueMessage<'a>,
                    sequence: u64,
                ) -> Result<InboundPlainMessage<'a>, rustls::Error> {
                    if message.payload.len() < 24 {
                        return Err(rustls::Error::DecryptError);
                    }
                    let mut nonce = [0u8; 12];
                    nonce[..4].copy_from_slice(&self.1);
                    nonce[4..].copy_from_slice(&message.payload[..8]);
                    let plaintext_len = message.payload.len() - 24;
                    let aad = cipher::make_tls12_aad(
                        sequence,
                        message.typ,
                        message.version,
                        plaintext_len,
                    );
                    {
                        let payload = &mut message.payload[8..];
                        let (plaintext, tag) = payload.split_at_mut(plaintext_len);
                        self.0
                            .decrypt_in_place_detached(
                                &nonce.into(),
                                &aad,
                                plaintext,
                                aes_gcm::Tag::from_slice(tag),
                            )
                            .map_err(|_| rustls::Error::DecryptError)?;
                    }
                    // Move only after authentication succeeds.
                    message.payload.rotate_left(8);
                    message.payload.truncate(plaintext_len);
                    Ok(message.into_plain_message())
                }
            }
        }
    };
}

#[cfg(feature = "tls12")]
impl_gcm_tls12!(Aes128Gcm, aes_gcm::Aes128Gcm, Aes128Gcm);
#[cfg(feature = "tls12")]
impl_gcm_tls12!(Aes256Gcm, aes_gcm::Aes256Gcm, Aes256Gcm);
