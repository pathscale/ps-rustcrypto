use alloc::boxed::Box;

use chacha20poly1305::{AeadInPlace, KeyInit, KeySizeUser};
use rustls::crypto::cipher::{
    self, AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv, MessageDecrypter,
    MessageEncrypter, OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload,
    Tls13AeadAlgorithm, UnsupportedOperationError,
};
use rustls::{ConnectionTrafficSecrets, ContentType, ProtocolVersion};

#[cfg(feature = "tls12")]
use rustls::crypto::cipher::{KeyBlockShape, Tls12AeadAlgorithm};

use super::{DecryptBufferAdapter, EncryptBufferAdapter};

pub struct Chacha20Poly1305;

impl Tls13AeadAlgorithm for Chacha20Poly1305 {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(Tls13Cipher(
            chacha20poly1305::ChaCha20Poly1305::new_from_slice(key.as_ref())
                .expect("rustls supplies the cipher's key length"),
            iv,
        ))
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        Box::new(Tls13Cipher(
            chacha20poly1305::ChaCha20Poly1305::new_from_slice(key.as_ref())
                .expect("rustls supplies the cipher's key length"),
            iv,
        ))
    }

    fn key_len(&self) -> usize {
        chacha20poly1305::ChaCha20Poly1305::key_size()
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv })
    }
}

struct Tls13Cipher(chacha20poly1305::ChaCha20Poly1305, Iv);

impl MessageEncrypter for Tls13Cipher {
    fn encrypt(
        &mut self,
        message: OutboundPlainMessage<'_>,
        sequence: u64,
    ) -> Result<OutboundOpaqueMessage, rustls::Error> {
        let total = self.encrypted_payload_len(message.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total);
        payload.extend_from_chunks(&message.payload);
        payload.extend_from_slice(&message.typ.to_array());
        let nonce = cipher::Nonce::new(&self.1, sequence).0;
        let aad = cipher::make_tls13_aad(total);
        self.0
            .encrypt_in_place(&nonce.into(), &aad, &mut EncryptBufferAdapter(&mut payload))
            .map_err(|_| rustls::Error::EncryptError)?;
        Ok(OutboundOpaqueMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            payload,
        ))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 17
    }
}

impl MessageDecrypter for Tls13Cipher {
    fn decrypt<'a>(
        &mut self,
        mut message: InboundOpaqueMessage<'a>,
        sequence: u64,
    ) -> Result<InboundPlainMessage<'a>, rustls::Error> {
        let payload = &mut message.payload;
        let nonce = cipher::Nonce::new(&self.1, sequence).0;
        let aad = cipher::make_tls13_aad(payload.len());
        self.0
            .decrypt_in_place(&nonce.into(), &aad, &mut DecryptBufferAdapter(payload))
            .map_err(|_| rustls::Error::DecryptError)?;
        message.into_tls13_unpadded_message()
    }
}

#[cfg(feature = "tls12")]
impl Tls12AeadAlgorithm for Chacha20Poly1305 {
    fn encrypter(&self, key: AeadKey, iv: &[u8], _: &[u8]) -> Box<dyn MessageEncrypter> {
        Box::new(Tls12Cipher(
            chacha20poly1305::ChaCha20Poly1305::new_from_slice(key.as_ref())
                .expect("rustls supplies the cipher's key length"),
            Iv::copy(iv),
        ))
    }

    fn decrypter(&self, key: AeadKey, iv: &[u8]) -> Box<dyn MessageDecrypter> {
        Box::new(Tls12Cipher(
            chacha20poly1305::ChaCha20Poly1305::new_from_slice(key.as_ref())
                .expect("rustls supplies the cipher's key length"),
            Iv::copy(iv),
        ))
    }

    fn key_block_shape(&self) -> KeyBlockShape {
        KeyBlockShape {
            enc_key_len: 32,
            fixed_iv_len: 12,
            explicit_nonce_len: 0,
        }
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: &[u8],
        _: &[u8],
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Chacha20Poly1305 {
            key,
            iv: Iv::copy(iv),
        })
    }
}

#[cfg(feature = "tls12")]
struct Tls12Cipher(chacha20poly1305::ChaCha20Poly1305, Iv);

#[cfg(feature = "tls12")]
impl MessageEncrypter for Tls12Cipher {
    fn encrypt(
        &mut self,
        message: OutboundPlainMessage<'_>,
        sequence: u64,
    ) -> Result<OutboundOpaqueMessage, rustls::Error> {
        let mut payload =
            PrefixedPayload::with_capacity(self.encrypted_payload_len(message.payload.len()));
        payload.extend_from_chunks(&message.payload);
        let nonce = cipher::Nonce::new(&self.1, sequence).0;
        let aad = cipher::make_tls12_aad(
            sequence,
            message.typ,
            message.version,
            message.payload.len(),
        );
        self.0
            .encrypt_in_place(&nonce.into(), &aad, &mut EncryptBufferAdapter(&mut payload))
            .map_err(|_| rustls::Error::EncryptError)?;
        Ok(OutboundOpaqueMessage::new(
            message.typ,
            message.version,
            payload,
        ))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 16
    }
}

#[cfg(feature = "tls12")]
impl MessageDecrypter for Tls12Cipher {
    fn decrypt<'a>(
        &mut self,
        mut message: InboundOpaqueMessage<'a>,
        sequence: u64,
    ) -> Result<InboundPlainMessage<'a>, rustls::Error> {
        if message.payload.len() < 16 {
            return Err(rustls::Error::DecryptError);
        }
        let nonce = cipher::Nonce::new(&self.1, sequence).0;
        let aad = cipher::make_tls12_aad(
            sequence,
            message.typ,
            message.version,
            message.payload.len() - 16,
        );
        self.0
            .decrypt_in_place(
                &nonce.into(),
                &aad,
                &mut DecryptBufferAdapter(&mut message.payload),
            )
            .map_err(|_| rustls::Error::DecryptError)?;
        Ok(message.into_plain_message())
    }
}
