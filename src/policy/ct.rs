//! Certificate Transparency: a certificate counts as publicly logged only with
//! enough valid SCTs from enough distinct log operators.
//!
//! SCTs come from three places: the certificate extension
//! (1.3.6.1.4.1.11129.2.4.2, signed over the precertificate), a stapled OCSP
//! response (1.3.6.1.4.1.11129.2.4.5) and the TLS signed_certificate_timestamp
//! extension (both signed over the final certificate). rustls 0.23 neither asks
//! for nor hands a verifier the TLS extension, so the verifier sees the first
//! two; evaluate takes the third for callers that have it.
//!
//! Each SCT is checked against the bundled Google and Apple log lists, ECDSA
//! P-256 logs only: an SCT from a log with another key never counts. The
//! policy is the one Chrome and Apple share: embedded SCTs need two from logs
//! of two distinct operators, three when the certificate lives longer than 180
//! days; SCTs delivered by OCSP or TLS need two from two operators. It is met
//! when either list's view of the logs satisfies it.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;

use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::VerifierBuilderError;
use rustls::{
    CertificateError, DigitallySignedStruct, DistinguishedName, Error, OtherError, RootCertStore,
    SignatureScheme,
};
use sha2::{Digest, Sha256};

#[path = "ct_logs.rs"]
mod ct_logs;

/// 1.3.6.1.4.1.11129.2.4.2, the embedded SCT list.
const EMBEDDED_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x04, 0x02];
/// 1.3.6.1.4.1.11129.2.4.5, the SCT list in an OCSP single response.
const OCSP_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x04, 0x05];

/// How a list treats SCTs from a log.
#[derive(Clone, Copy, Debug)]
enum Status {
    /// Pending, rejected, or absent from the list.
    Never,
    /// Usable, qualified or read-only.
    Always,
    /// Retired: SCTs stamped before this time, in milliseconds, still count.
    Before(u64),
}

impl Status {
    fn counts(self, timestamp: u64) -> bool {
        match self {
            Self::Never => false,
            Self::Always => true,
            Self::Before(retired) => timestamp < retired,
        }
    }
}

/// One ECDSA P-256 log from the bundled lists.
struct Log {
    id: [u8; 32],
    /// The uncompressed SEC1 point.
    key: [u8; 65],
    google: Status,
    google_operator: &'static str,
    apple: Status,
    apple_operator: &'static str,
}

/// Why a certificate failed the CT policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotLogged {
    /// SCTs found in every source, valid or not.
    pub found: usize,
    /// The most valid SCTs, from distinct logs, that either list accepts.
    pub valid: usize,
    /// Distinct operators behind those.
    pub operators: usize,
    /// Embedded SCTs the certificate lifetime calls for.
    pub required: usize,
}

impl fmt::Display for NotLogged {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "certificate not publicly logged: {} valid SCTs from {} operators of {} found, policy needs {} from at least 2 operators",
            self.valid, self.operators, self.found, self.required
        )
    }
}

impl core::error::Error for NotLogged {}

/// What a compliant certificate showed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Logged {
    /// Valid SCTs, from distinct logs, either list accepts.
    pub valid: usize,
    /// Distinct operators behind those.
    pub operators: usize,
}

/// Whether error is a certificate failing the CT policy.
pub fn is_not_logged(error: &Error) -> bool {
    not_logged(error).is_some()
}

/// The CT failure inside error, if that is what it is.
pub fn not_logged(error: &Error) -> Option<&NotLogged> {
    match error {
        Error::InvalidCertificate(CertificateError::Other(other)) => {
            other.0.downcast_ref::<NotLogged>()
        }
        _ => None,
    }
}

/// Check the SCTs for end_entity under the CT policy.
///
/// intermediates supplies the issuer, whose key the precertificate SCTs sign
/// over. ocsp is the stapled response, empty when there is none, and tls is
/// the body of the TLS signed_certificate_timestamp extension, empty when
/// there is none.
pub fn evaluate(
    end_entity: &[u8],
    intermediates: &[&[u8]],
    ocsp: &[u8],
    tls: &[u8],
    now: UnixTime,
) -> Result<Logged, NotLogged> {
    let now_ms = now.as_secs().saturating_mul(1000);
    let leaf = cert_fields(end_entity);
    let lifetime = leaf
        .as_ref()
        .and_then(|leaf| leaf.lifetime)
        .unwrap_or(u64::MAX);
    let required = if lifetime <= 180 * 86_400 { 2 } else { 3 };

    let mut found = 0;
    let mut valid: Vec<Valid> = Vec::new();

    // Embedded: signed over the precertificate TBS and the issuer key hash.
    let mut embedded = Vec::new();
    find_extension(end_entity, EMBEDDED_OID, 8, &mut embedded);
    if !embedded.is_empty() {
        let tbs = precert_tbs(end_entity);
        let issuers: Vec<[u8; 32]> = match &leaf {
            Some(leaf) => intermediates
                .iter()
                .filter_map(|der| cert_fields(der))
                .filter(|issuer| issuer.subject == leaf.issuer)
                .map(|issuer| Sha256::digest(issuer.spki).into())
                .collect(),
            None => Vec::new(),
        };
        for list in embedded {
            for sct in sct_list(list) {
                found += 1;
                let Some(sct) = parse_sct(sct) else { continue };
                let Some(tbs) = &tbs else { continue };
                let accepted = issuers.iter().any(|hash| {
                    let mut entry = Vec::with_capacity(tbs.len() + 37);
                    entry.extend_from_slice(&[0, 1]);
                    entry.extend_from_slice(hash);
                    push_u24(&mut entry, tbs);
                    sct.verify(&entry, now_ms)
                });
                if accepted {
                    push_valid(&mut valid, &sct, true);
                }
            }
        }
    }

    // Delivered: signed over the certificate itself.
    let mut delivered = Vec::new();
    if !ocsp.is_empty() {
        find_extension(ocsp, OCSP_OID, 8, &mut delivered);
    }
    if !tls.is_empty() {
        delivered.push(tls);
    }
    if !delivered.is_empty() {
        let mut entry = Vec::with_capacity(end_entity.len() + 5);
        entry.extend_from_slice(&[0, 0]);
        push_u24(&mut entry, end_entity);
        for list in delivered {
            for sct in sct_list(list) {
                found += 1;
                let Some(sct) = parse_sct(sct) else { continue };
                if sct.verify(&entry, now_ms) {
                    push_valid(&mut valid, &sct, false);
                }
            }
        }
    }

    let mut best = (0, 0);
    for side in [Side::Google, Side::Apple] {
        let embedded = tally(&valid, side, true);
        let delivered = tally(&valid, side, false);
        if (embedded.0 >= required && embedded.1 >= 2) || (delivered.0 >= 2 && delivered.1 >= 2) {
            let (logs, operators) = if embedded.0 >= required {
                embedded
            } else {
                delivered
            };
            return Ok(Logged {
                valid: logs,
                operators,
            });
        }
        for candidate in [embedded, delivered] {
            if candidate > best {
                best = candidate;
            }
        }
    }
    Err(NotLogged {
        found,
        valid: best.0,
        operators: best.1,
        required,
    })
}

/// A server certificate verifier that runs another, then the CT policy.
#[derive(Debug)]
pub struct CtVerifier {
    inner: Arc<dyn ServerCertVerifier>,
}

impl CtVerifier {
    /// CT on top of inner, which validates the chain first.
    pub fn new(inner: Arc<dyn ServerCertVerifier>) -> Arc<Self> {
        Arc::new(Self { inner })
    }

    /// CT on top of the ECC-only chain policy.
    pub fn ecc_only(roots: RootCertStore) -> Result<Arc<Self>, VerifierBuilderError> {
        Ok(Self::new(super::EccOnlyVerifier::new(roots)?))
    }
}

impl ServerCertVerifier for CtVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let verified = self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;
        let intermediates: Vec<&[u8]> = intermediates.iter().map(|der| der.as_ref()).collect();
        evaluate(end_entity.as_ref(), &intermediates, ocsp_response, &[], now).map_err(
            |error| Error::InvalidCertificate(CertificateError::Other(OtherError(Arc::new(error)))),
        )?;
        Ok(verified)
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

    fn requires_raw_public_keys(&self) -> bool {
        self.inner.requires_raw_public_keys()
    }

    fn root_hint_subjects(&self) -> Option<&[DistinguishedName]> {
        self.inner.root_hint_subjects()
    }
}

#[derive(Clone, Copy)]
enum Side {
    Google,
    Apple,
}

struct Valid {
    log: &'static Log,
    timestamp: u64,
    embedded: bool,
}

fn push_valid(valid: &mut Vec<Valid>, sct: &Sct<'_>, embedded: bool) {
    // The same log twice is one SCT.
    if valid
        .iter()
        .any(|seen| seen.embedded == embedded && seen.log.id == sct.log.id)
    {
        return;
    }
    valid.push(Valid {
        log: sct.log,
        timestamp: sct.timestamp,
        embedded,
    });
}

/// Distinct logs and distinct operators a list accepts among valid SCTs.
fn tally(valid: &[Valid], side: Side, embedded: bool) -> (usize, usize) {
    let mut logs = 0;
    let mut operators: Vec<&str> = Vec::new();
    for sct in valid.iter().filter(|sct| sct.embedded == embedded) {
        let (status, operator) = match side {
            Side::Google => (sct.log.google, sct.log.google_operator),
            Side::Apple => (sct.log.apple, sct.log.apple_operator),
        };
        if !status.counts(sct.timestamp) {
            continue;
        }
        logs += 1;
        if !operators.contains(&operator) {
            operators.push(operator);
        }
    }
    (logs, operators.len())
}

struct Sct<'a> {
    log: &'static Log,
    timestamp: u64,
    extensions: &'a [u8],
    signature: &'a [u8],
}

impl Sct<'_> {
    /// Verify over entry, the entry type and signed entry of the RFC 6962
    /// digitally-signed struct.
    fn verify(&self, entry: &[u8], now_ms: u64) -> bool {
        if self.timestamp > now_ms {
            return false;
        }
        let mut signed = Vec::with_capacity(entry.len() + 12 + self.extensions.len());
        signed.extend_from_slice(&[0, 0]); // v1, certificate_timestamp
        signed.extend_from_slice(&self.timestamp.to_be_bytes());
        signed.extend_from_slice(entry);
        signed.extend_from_slice(&(self.extensions.len() as u16).to_be_bytes());
        signed.extend_from_slice(self.extensions);
        let Ok(key) = VerifyingKey::from_sec1_bytes(&self.log.key) else {
            return false;
        };
        let Ok(signature) = Signature::from_der(self.signature) else {
            return false;
        };
        key.verify(&signed, &signature).is_ok()
    }
}

/// An SCT from a bundled log, with SHA-256 and ECDSA; anything else is None.
fn parse_sct(input: &[u8]) -> Option<Sct<'_>> {
    let mut reader = Reader(input);
    if reader.u8()? != 0 {
        return None;
    }
    let id = reader.take(32)?;
    let timestamp = u64::from_be_bytes(reader.take(8)?.try_into().ok()?);
    let extensions = reader.vec16()?;
    // SHA-256 (4) with ECDSA (3).
    if reader.u8()? != 4 || reader.u8()? != 3 {
        return None;
    }
    let signature = reader.vec16()?;
    if !reader.0.is_empty() {
        return None;
    }
    let index = ct_logs::LOGS
        .binary_search_by(|log| log.id.as_slice().cmp(id))
        .ok()?;
    Some(Sct {
        log: &ct_logs::LOGS[index],
        timestamp,
        extensions,
        signature,
    })
}

/// The SCTs in a TLS-encoded SignedCertificateTimestampList.
fn sct_list(input: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut outer = Reader(input);
    let Some(list) = outer.vec16() else {
        return out;
    };
    let mut reader = Reader(list);
    while !reader.0.is_empty() {
        match reader.vec16() {
            Some(sct) => out.push(sct),
            None => break,
        }
    }
    out
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Option<&'a [u8]> {
        if self.0.len() < count {
            return None;
        }
        let (head, tail) = self.0.split_at(count);
        self.0 = tail;
        Some(head)
    }

    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }

    fn vec16(&mut self) -> Option<&'a [u8]> {
        let length = self.take(2)?;
        self.take(u16::from_be_bytes([length[0], length[1]]) as usize)
    }
}

/// The SCT list in every Extension with this OID, searched through the DER
/// tree, OCTET STRING wrappers included, to depth levels.
fn find_extension<'a>(der: &'a [u8], oid: &[u8], depth: u8, out: &mut Vec<&'a [u8]>) {
    let mut rest = der;
    while let Some((tag, contents, _, next)) = tlv(rest) {
        if tag == 0x30 {
            if let Some(value) = extension_value(contents, oid) {
                out.push(value);
            } else if depth > 0 {
                find_extension(contents, oid, depth - 1, out);
            }
        } else if (tag & 0x20 != 0 || tag == 0x04) && depth > 0 {
            find_extension(contents, oid, depth - 1, out);
        }
        rest = next;
    }
}

/// The SCT list inside an Extension with this OID: extnValue is an OCTET
/// STRING holding an OCTET STRING holding the TLS-encoded list.
fn extension_value<'a>(extension: &'a [u8], oid: &[u8]) -> Option<&'a [u8]> {
    let (0x06, found, _, rest) = tlv(extension)? else {
        return None;
    };
    if found != oid {
        return None;
    }
    let (mut tag, mut value, _, mut rest) = tlv(rest)?;
    if tag == 0x01 {
        (tag, value, _, rest) = tlv(rest)?;
    }
    if tag != 0x04 || !rest.is_empty() {
        return None;
    }
    let (0x04, list, _, []) = tlv(value)? else {
        return None;
    };
    Some(list)
}

/// The TBSCertificate with the embedded SCT extension removed, which is what
/// the log signed for a precertificate.
fn precert_tbs(certificate: &[u8]) -> Option<Vec<u8>> {
    let (0x30, certificate, _, _) = tlv(certificate)? else {
        return None;
    };
    let (0x30, tbs, _, _) = tlv(certificate)? else {
        return None;
    };
    let mut fields = Vec::with_capacity(tbs.len());
    let mut rest = tbs;
    while !rest.is_empty() {
        let (tag, contents, whole, next) = tlv(rest)?;
        if tag == 0xa3 {
            let (0x30, extensions, _, _) = tlv(contents)? else {
                return None;
            };
            let mut kept = Vec::with_capacity(extensions.len());
            let mut list = extensions;
            while !list.is_empty() {
                let (_, extension, whole, next) = tlv(list)?;
                let (_, oid, _, _) = tlv(extension)?;
                if oid != EMBEDDED_OID {
                    kept.extend_from_slice(whole);
                }
                list = next;
            }
            let mut sequence = Vec::with_capacity(kept.len() + 4);
            push_tlv(&mut sequence, 0x30, &kept);
            push_tlv(&mut fields, 0xa3, &sequence);
        } else {
            fields.extend_from_slice(whole);
        }
        rest = next;
    }
    let mut out = Vec::with_capacity(fields.len() + 4);
    push_tlv(&mut out, 0x30, &fields);
    Some(out)
}

struct Fields<'a> {
    issuer: &'a [u8],
    subject: &'a [u8],
    /// The whole SubjectPublicKeyInfo element, which the issuer key hash covers.
    spki: &'a [u8],
    /// notAfter minus notBefore, in seconds.
    lifetime: Option<u64>,
}

fn cert_fields(der: &[u8]) -> Option<Fields<'_>> {
    let (0x30, certificate, _, _) = tlv(der)? else {
        return None;
    };
    let (0x30, tbs, _, _) = tlv(certificate)? else {
        return None;
    };
    let (tag, _, _, after) = tlv(tbs)?;
    let rest = if tag == 0xa0 { after } else { tbs };
    let (_, _, _, rest) = tlv(rest)?; // serialNumber
    let (_, _, _, rest) = tlv(rest)?; // signature
    let (_, issuer, _, rest) = tlv(rest)?;
    let (_, validity, _, rest) = tlv(rest)?;
    let (_, subject, _, rest) = tlv(rest)?;
    let (0x30, _, spki, _) = tlv(rest)? else {
        return None;
    };
    let lifetime = (|| {
        let (before_tag, before, _, rest) = tlv(validity)?;
        let (after_tag, after, _, _) = tlv(rest)?;
        time(after_tag, after)?.checked_sub(time(before_tag, before)?)
    })();
    Some(Fields {
        issuer,
        subject,
        spki,
        lifetime,
    })
}

/// UTCTime or GeneralizedTime, in Unix seconds.
fn time(tag: u8, text: &[u8]) -> Option<u64> {
    let (year, rest) = match (tag, text.len()) {
        (0x17, 13) => {
            let year = number(&text[..2])?;
            (
                if year < 50 { 2000 + year } else { 1900 + year },
                &text[2..],
            )
        }
        (0x18, 15) => (number(&text[..4])?, &text[4..]),
        _ => return None,
    };
    if rest[10] != b'Z' {
        return None;
    }
    let month = number(&rest[0..2])?;
    let day = number(&rest[2..4])?;
    let hour = number(&rest[4..6])?;
    let minute = number(&rest[6..8])?;
    let second = number(&rest[8..10])?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let days = days_from_civil(year as i64, month as i64, day as i64);
    let seconds = days * 86_400 + (hour * 3600 + minute * 60 + second) as i64;
    u64::try_from(seconds).ok()
}

fn number(digits: &[u8]) -> Option<u64> {
    digits.iter().try_fold(0u64, |value, digit| {
        digit
            .is_ascii_digit()
            .then(|| value * 10 + u64::from(digit - b'0'))
    })
}

/// Days since 1970-01-01 of a proleptic Gregorian date.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let shifted = (month + 9) % 12;
    let day_of_year = (153 * shifted + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// Tag, contents, the whole element, and what follows it.
type Tlv<'a> = (u8, &'a [u8], &'a [u8], &'a [u8]);

/// One DER element.
fn tlv(input: &[u8]) -> Option<Tlv<'_>> {
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
    let header = input.len() - rest.len();
    Some((
        tag,
        &rest[..length],
        &input[..header + length],
        &rest[length..],
    ))
}

fn push_tlv(out: &mut Vec<u8>, tag: u8, contents: &[u8]) {
    out.push(tag);
    let length = contents.len();
    if length < 0x80 {
        out.push(length as u8);
    } else {
        let bytes = length.to_be_bytes();
        let skip = bytes.iter().take_while(|byte| **byte == 0).count();
        out.push(0x80 | (bytes.len() - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
    out.extend_from_slice(contents);
}

fn push_u24(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes()[1..]);
    out.extend_from_slice(bytes);
}
