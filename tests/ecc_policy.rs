//! ECC-only chain policy over a real in-memory TLS 1.3 handshake: a chain
//! with an RSA leaf, an RSA intermediate, or an RSA trust anchor is refused
//! with unsupported_certificate, and an all-ECC chain completes.
//!
//! The RSA keys come from the public root bundles and are never used to
//! verify anything: the refusal happens before any signature is checked.

use std::sync::Arc;

use pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use ps_rustcrypto::policy::{is_rsa_refusal, EccOnlyVerifier};
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, DnType, IsCa, KeyPair};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::version::TLS13;
use rustls::{
    AlertDescription, ClientConfig, ClientConnection, Error, RootCertStore, ServerConfig,
    ServerConnection,
};

/// rsaEncryption, 1.2.840.113549.1.1.1, as a DER element.
const RSA_OID: &[u8] = &[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
];

fn holds_rsa(der: &[u8]) -> bool {
    der.windows(RSA_OID.len()).any(|window| window == RSA_OID)
}

fn rsa_certificate() -> CertificateDer<'static> {
    webpki_root_certs::TLS_SERVER_ROOT_CERTS
        .iter()
        .find(|cert| holds_rsa(cert.as_ref()))
        .expect("an RSA root in the bundle")
        .clone()
}

struct Pki {
    root: CertifiedIssuer<'static, KeyPair>,
    leaf: CertificateDer<'static>,
    leaf_key: KeyPair,
}

fn pki() -> Pki {
    let mut params = CertificateParams::new(Vec::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(DnType::CommonName, "ECC policy test root");
    let root = CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap();
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec![String::from("localhost")])
        .unwrap()
        .signed_by(&leaf_key, &root)
        .unwrap()
        .der()
        .clone();
    Pki {
        root,
        leaf,
        leaf_key,
    }
}

fn roots(pki: &Pki) -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.add(pki.root.der().clone()).unwrap();
    roots
}

#[derive(Debug)]
struct Fixed(Arc<CertifiedKey>);

impl ResolvesServerCert for Fixed {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

struct Outcome {
    client: Option<Error>,
    server: Option<Error>,
    complete: bool,
}

fn handshake(chain: Vec<CertificateDer<'static>>, key: &KeyPair, roots: RootCertStore) -> Outcome {
    let provider = Arc::new(ps_rustcrypto::provider());
    let signing = provider
        .key_provider
        .load_private_key(PrivateKeyDer::Pkcs8(key.serialize_der().into()))
        .unwrap();
    let server = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(Fixed(Arc::new(CertifiedKey::new(chain, signing)))));
    let client = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(EccOnlyVerifier::new(roots).unwrap())
        .with_no_client_auth();
    let mut server = ServerConnection::new(Arc::new(server)).unwrap();
    let mut client =
        ClientConnection::new(Arc::new(client), ServerName::try_from("localhost").unwrap())
            .unwrap();

    let mut outcome = Outcome {
        client: None,
        server: None,
        complete: false,
    };
    for _ in 0..8 {
        let mut bytes = Vec::new();
        while client.wants_write() {
            client.write_tls(&mut bytes).unwrap();
        }
        if !bytes.is_empty() {
            server.read_tls(&mut bytes.as_slice()).unwrap();
            if let Err(error) = server.process_new_packets() {
                outcome.server = Some(error);
                return outcome;
            }
        }
        if outcome.client.is_some() {
            return outcome;
        }
        let mut bytes = Vec::new();
        while server.wants_write() {
            server.write_tls(&mut bytes).unwrap();
        }
        if !bytes.is_empty() {
            client.read_tls(&mut bytes.as_slice()).unwrap();
            if let Err(error) = client.process_new_packets() {
                outcome.client = Some(error);
                continue;
            }
        }
        if !client.is_handshaking() && !server.is_handshaking() {
            outcome.complete = true;
            return outcome;
        }
    }
    outcome
}

fn assert_refused(outcome: Outcome) {
    assert!(!outcome.complete);
    let client = outcome.client.expect("client refused the chain");
    assert!(
        is_rsa_refusal(&client),
        "unexpected client error {client:?}"
    );
    assert_eq!(
        outcome.server,
        Some(Error::AlertReceived(
            AlertDescription::UnsupportedCertificate
        ))
    );
}

#[test]
fn rsa_leaf_is_refused_with_alert_43() {
    let pki = pki();
    let outcome = handshake(vec![rsa_certificate()], &pki.leaf_key, roots(&pki));
    assert_refused(outcome);
}

#[test]
fn rsa_intermediate_is_refused_with_alert_43() {
    let pki = pki();
    let chain = vec![pki.leaf.clone(), rsa_certificate()];
    let outcome = handshake(chain, &pki.leaf_key, roots(&pki));
    assert_refused(outcome);
}

#[test]
fn rsa_root_is_refused_with_alert_43() {
    let pki = pki();
    let rsa_key = webpki_roots::TLS_SERVER_ROOTS
        .iter()
        .find(|anchor| holds_rsa(anchor.subject_public_key_info.as_ref()))
        .expect("an RSA anchor in the bundle")
        .subject_public_key_info
        .clone();
    // The anchor the leaf names, carrying an RSA key.
    let mut roots = roots(&pki);
    roots.roots[0].subject_public_key_info = rsa_key;
    let verifier = EccOnlyVerifier::new(roots.clone()).err();
    // Every anchor is dropped, so the store is empty and webpki refuses to
    // build. Keep one unrelated ECC anchor so the verifier exists.
    assert!(verifier.is_some());
    let other = pki_other_root();
    roots.add(other).unwrap();
    let outcome = handshake(vec![pki.leaf.clone()], &pki.leaf_key, roots);
    assert_refused(outcome);
}

fn pki_other_root() -> CertificateDer<'static> {
    let mut params = CertificateParams::new(Vec::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(DnType::CommonName, "Unrelated ECC root");
    params
        .self_signed(&KeyPair::generate().unwrap())
        .unwrap()
        .der()
        .clone()
}

/// A server may append its ECC root cross-signed by an RSA root, as
/// Cloudflare (GTS Root R4 by GlobalSign Root CA) and Let's Encrypt (ISRG
/// Root X2 by X1) do. The path ends at the ECC anchor and never uses that
/// copy, so it must not be refused.
#[test]
fn rsa_cross_signed_extra_is_ignored() {
    let pki = pki();
    let mut params = CertificateParams::new(Vec::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(DnType::CommonName, "Legacy RSA root");
    let legacy = CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap();
    let mut copy = CertificateParams::new(Vec::new()).unwrap();
    copy.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    copy.distinguished_name
        .push(DnType::CommonName, "ECC policy test root");
    let cross = copy
        .signed_by(&KeyPair::generate().unwrap(), &legacy)
        .unwrap()
        .der()
        .clone();
    let rsa_key = webpki_roots::TLS_SERVER_ROOTS
        .iter()
        .find(|anchor| holds_rsa(anchor.subject_public_key_info.as_ref()))
        .unwrap()
        .subject_public_key_info
        .clone();
    let mut roots = roots(&pki);
    roots.add(legacy.der().clone()).unwrap();
    roots.roots[1].subject_public_key_info = rsa_key;
    let outcome = handshake(vec![pki.leaf.clone(), cross], &pki.leaf_key, roots);
    assert!(outcome.client.is_none(), "{:?}", outcome.client);
    assert!(outcome.complete);
}

#[test]
fn all_ecc_chain_completes() {
    let pki = pki();
    let outcome = handshake(vec![pki.leaf.clone()], &pki.leaf_key, roots(&pki));
    assert!(outcome.client.is_none(), "{:?}", outcome.client);
    assert!(outcome.server.is_none(), "{:?}", outcome.server);
    assert!(outcome.complete);
}

#[test]
fn bundle_rsa_anchors_are_dropped() {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let verifier = EccOnlyVerifier::new(roots).unwrap();
    assert!(verifier.refused_anchors() > 0);
}
