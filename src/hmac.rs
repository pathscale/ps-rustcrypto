use alloc::boxed::Box;

use digest::OutputSizeUser;
use hmac::{KeyInit, Mac};
use rustls::crypto;
use sha2::Sha256;

struct HmacSha256;

impl crypto::hmac::Hmac for HmacSha256 {
    fn with_key(&self, key: &[u8]) -> Box<dyn crypto::hmac::Key> {
        Box::new(HmacKeySha256(
            hmac::Hmac::<Sha256>::new_from_slice(key)
                .expect("HMAC accepts every key length"),
        ))
    }

    fn hash_output_len(&self) -> usize {
        Sha256::output_size()
    }
}

struct HmacKeySha256(hmac::Hmac<Sha256>);

impl crypto::hmac::Key for HmacKeySha256 {
    fn sign_concat(
        &self,
        first: &[u8],
        middle: &[&[u8]],
        last: &[u8],
    ) -> crypto::hmac::Tag {
        let mut context = self.0.clone();
        context.update(first);
        for part in middle {
            context.update(part);
        }
        context.update(last);
        crypto::hmac::Tag::new(&context.finalize().into_bytes())
    }

    fn tag_len(&self) -> usize {
        Sha256::output_size()
    }
}

pub const SHA256: &dyn crypto::hmac::Hmac = &HmacSha256;
