use alloc::boxed::Box;

use legacy_bullshit::tls13::{RecordKey, TAG_LEN};
use rustls::crypto::cipher::{
    AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv, MessageDecrypter, MessageEncrypter,
    OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload, Tls13AeadAlgorithm,
    UnsupportedOperationError,
};
use rustls::{ConnectionTrafficSecrets, ContentType, Error, ProtocolVersion};

pub(crate) struct Aes128Gcm;

impl Tls13AeadAlgorithm for Aes128Gcm {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(Tls13Cipher::new(key, iv))
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        Box::new(Tls13Cipher::new(key, iv))
    }

    fn key_len(&self) -> usize {
        16
    }

    fn extract_keys(
        &self,
        _: AeadKey,
        _: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Err(UnsupportedOperationError)
    }
}

struct Tls13Cipher(RecordKey);

impl Tls13Cipher {
    fn new(key: AeadKey, iv: Iv) -> Self {
        let key = key
            .as_ref()
            .try_into()
            .expect("rustls supplies a 16-byte key");
        let iv = iv
            .as_ref()
            .try_into()
            .expect("rustls supplies a 12-byte IV");
        Self(RecordKey::new(key, iv))
    }
}

impl MessageEncrypter for Tls13Cipher {
    fn encrypt(
        &mut self,
        message: OutboundPlainMessage<'_>,
        sequence: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        let mut payload =
            PrefixedPayload::with_capacity(self.encrypted_payload_len(message.payload.len()));
        payload.extend_from_chunks(&message.payload);
        payload.extend_from_slice(&message.typ.to_array());
        let tag = self
            .0
            .seal_in_place(sequence, payload.as_mut())
            .map_err(|_| Error::EncryptError)?;
        payload.extend_from_slice(&tag);
        Ok(OutboundOpaqueMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            payload,
        ))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + TAG_LEN
    }
}

impl MessageDecrypter for Tls13Cipher {
    fn decrypt<'a>(
        &mut self,
        mut message: InboundOpaqueMessage<'a>,
        sequence: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let len = self
            .0
            .open_in_place(sequence, &mut message.payload)
            .map_err(|_| Error::DecryptError)?;
        message.payload.truncate(len);
        message.into_tls13_unpadded_message()
    }
}
