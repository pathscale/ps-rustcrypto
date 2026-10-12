//! ECC-only certificate policy.
//!
//! A chain that holds an RSA key, or any key other than ECDSA or Ed25519, is
//! refused before any of its signatures are checked. That covers the leaf,
//! every intermediate, and the trust anchor the chain points at: anchors with
//! other keys are dropped from the store and remembered, so a chain issued by
//! one is refused by name rather than failing as an unknown issuer.
//!
//! The refusal goes out as unsupported_certificate (alert 43). rustls picks
//! the alert from the error, and the only certificate error it maps to 43 is
//! InvalidPurpose, so the refusal travels as InvalidPurposeContext naming the
//! wanted and the presented key algorithm. is_key_type_refusal tells it apart
//! from a genuine extended key usage mismatch.

use alloc::sync::Arc;
use alloc::vec::Vec;

use pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{VerifierBuilderError, WebPkiServerVerifier};
use rustls::{
    CertificateError, DigitallySignedStruct, DistinguishedName, Error, ExtendedKeyPurpose,
    RootCertStore, SignatureScheme,
};

/// id-ecPublicKey, 1.2.840.10045.2.1, as DER contents.
const EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
/// Ed25519, 1.3.101.112, as DER contents.
const ED25519: &[u8] = &[0x2b, 0x65, 0x70];
/// The required algorithm a refusal names: id-ecPublicKey.
const REQUIRED: &[usize] = &[1, 2, 840, 10045, 2, 1];
/// rsaEncryption, 1.2.840.113549.1.1.1.
pub const RSA_ENCRYPTION: &[usize] = &[1, 2, 840, 113549, 1, 1, 1];
/// RSASSA-PSS, 1.2.840.113549.1.1.10.
pub const RSASSA_PSS: &[usize] = &[1, 2, 840, 113549, 1, 1, 10];

/// A server certificate verifier that accepts ECDSA and Ed25519 keys only.
#[derive(Debug)]
pub struct EccOnlyVerifier {
    inner: Arc<WebPkiServerVerifier>,
    /// Subjects of the anchors that were kept.
    kept: Vec<Vec<u8>>,
    /// Subject and key algorithm of every anchor that was dropped.
    refused: Vec<(Vec<u8>, Vec<u8>)>,
}

impl EccOnlyVerifier {
    /// Build over roots, dropping every anchor whose key is not ECC.
    pub fn new(roots: RootCertStore) -> Result<Arc<Self>, VerifierBuilderError> {
        let mut store = RootCertStore::empty();
        let mut kept = Vec::new();
        let mut refused = Vec::new();
        for anchor in roots.roots {
            let subject = unwrap(anchor.subject.as_ref()).to_vec();
            match key_algorithm(unwrap(anchor.subject_public_key_info.as_ref())) {
                Some(oid) if allowed(oid) => {
                    kept.push(subject);
                    store.roots.push(anchor);
                }
                oid => refused.push((subject, oid.unwrap_or(&[]).to_vec())),
            }
        }
        let inner = WebPkiServerVerifier::builder_with_provider(
            Arc::new(store),
            Arc::new(crate::provider()),
        )
        .build()?;
        Ok(Arc::new(Self {
            inner,
            kept,
            refused,
        }))
    }

    /// How many anchors were dropped for their key type.
    pub fn refused_anchors(&self) -> usize {
        self.refused.len()
    }

    fn check(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
    ) -> Result<(), Error> {
        let mut top = None;
        for der in core::iter::once(end_entity).chain(intermediates) {
            // Unparseable input is left to webpki, which reports it properly.
            let Some(cert) = parse(der.as_ref()) else {
                continue;
            };
            if !allowed(cert.key) {
                return Err(refusal(cert.key));
            }
            top = Some(cert.issuer);
        }
        if let Some(issuer) = top {
            if !self.kept.iter().any(|subject| subject.as_slice() == issuer) {
                if let Some((_, oid)) = self
                    .refused
                    .iter()
                    .find(|(subject, _)| subject.as_slice() == issuer)
                {
                    return Err(refusal(oid));
                }
            }
        }
        Ok(())
    }
}

impl ServerCertVerifier for EccOnlyVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        self.check(end_entity, intermediates)?;
        self.inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }

    fn root_hint_subjects(&self) -> Option<&[DistinguishedName]> {
        self.inner.root_hint_subjects()
    }
}

/// Whether error is this policy refusing a key type.
pub fn is_key_type_refusal(error: &Error) -> bool {
    refused_algorithm(error).is_some()
}

/// Whether error is this policy refusing an RSA key.
pub fn is_rsa_refusal(error: &Error) -> bool {
    refused_algorithm(error).is_some_and(|oid| oid == RSA_ENCRYPTION || oid == RSASSA_PSS)
}

/// The key algorithm a refusal names, as OID arcs.
pub fn refused_algorithm(error: &Error) -> Option<&[usize]> {
    match error {
        Error::InvalidCertificate(CertificateError::InvalidPurposeContext {
            required: ExtendedKeyPurpose::Other(required),
            presented,
        }) if required.as_slice() == REQUIRED => match presented.as_slice() {
            [ExtendedKeyPurpose::Other(oid)] => Some(oid.as_slice()),
            _ => None,
        },
        _ => None,
    }
}

fn refusal(oid: &[u8]) -> Error {
    Error::InvalidCertificate(CertificateError::InvalidPurposeContext {
        required: ExtendedKeyPurpose::Other(REQUIRED.to_vec()),
        presented: alloc::vec![ExtendedKeyPurpose::Other(arcs(oid))],
    })
}

fn allowed(oid: &[u8]) -> bool {
    oid == EC_PUBLIC_KEY || oid == ED25519
}

struct Parsed<'a> {
    issuer: &'a [u8],
    key: &'a [u8],
}

/// The issuer name and key algorithm of a DER certificate.
fn parse(der: &[u8]) -> Option<Parsed<'_>> {
    let (0x30, certificate, _) = element(der)? else {
        return None;
    };
    let (0x30, tbs, _) = element(certificate)? else {
        return None;
    };
    let (tag, _, after) = element(tbs)?;
    // The explicit version is optional.
    let rest = if tag == 0xa0 { after } else { tbs };
    let (_, _, rest) = element(rest)?; // serialNumber
    let (_, _, rest) = element(rest)?; // signature
    let (_, issuer, rest) = element(rest)?;
    let (_, _, rest) = element(rest)?; // validity
    let (_, _, rest) = element(rest)?; // subject
    let (0x30, spki, _) = element(rest)? else {
        return None;
    };
    Some(Parsed {
        issuer,
        key: key_algorithm(spki)?,
    })
}

/// The algorithm OID in SubjectPublicKeyInfo contents.
fn key_algorithm(spki: &[u8]) -> Option<&[u8]> {
    let (0x30, algorithm, _) = element(spki)? else {
        return None;
    };
    let (0x06, oid, _) = element(algorithm)? else {
        return None;
    };
    Some(oid)
}

/// The contents of a lone SEQUENCE, or the input when it is already contents.
/// Trust anchors store contents; some stores keep the whole element.
fn unwrap(value: &[u8]) -> &[u8] {
    match element(value) {
        Some((0x30, contents, [])) => contents,
        _ => value,
    }
}

/// One DER element: its tag, its contents, and what follows it.
fn element(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = input.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (length, rest) = if first < 0x80 {
        (first as usize, rest)
    } else {
        let count = (first & 0x7f) as usize;
        if count == 0 || count > 4 || rest.len() < count {
            return None;
        }
        let length = rest[..count]
            .iter()
            .fold(0usize, |length, byte| (length << 8) | *byte as usize);
        (length, &rest[count..])
    };
    if rest.len() < length {
        return None;
    }
    Some((tag, &rest[..length], &rest[length..]))
}

/// OID contents as arcs, for the error report.
fn arcs(oid: &[u8]) -> Vec<usize> {
    let mut out = Vec::new();
    let mut value = 0usize;
    for byte in oid {
        value = (value << 7) | (byte & 0x7f) as usize;
        if byte & 0x80 == 0 {
            if out.is_empty() {
                let first = if value < 80 { value / 40 } else { 2 };
                out.push(first);
                out.push(value - first * 40);
            } else {
                out.push(value);
            }
            value = 0;
        }
    }
    out
}
