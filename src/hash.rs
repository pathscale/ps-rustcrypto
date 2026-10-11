use alloc::boxed::Box;

use digest::{Digest, OutputSizeUser};
use rustls::crypto::{self, hash};
use sha2::Sha256;

struct HashSha256;

impl hash::Hash for HashSha256 {
    fn start(&self) -> Box<dyn hash::Context> {
        Box::new(HashContextSha256(Sha256::new()))
    }

    fn hash(&self, data: &[u8]) -> hash::Output {
        hash::Output::new(&Sha256::digest(data))
    }

    fn output_len(&self) -> usize {
        <Sha256 as OutputSizeUser>::output_size()
    }

    fn algorithm(&self) -> hash::HashAlgorithm {
        hash::HashAlgorithm::SHA256
    }
}

struct HashContextSha256(Sha256);

impl hash::Context for HashContextSha256 {
    fn fork_finish(&self) -> hash::Output {
        hash::Output::new(&self.0.clone().finalize())
    }

    fn fork(&self) -> Box<dyn hash::Context> {
        Box::new(HashContextSha256(self.0.clone()))
    }

    fn finish(self: Box<Self>) -> hash::Output {
        hash::Output::new(&self.0.finalize())
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
}

pub const SHA256: &dyn crypto::hash::Hash = &HashSha256;
