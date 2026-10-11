# ps-rustcrypto

A synchronous RustCrypto provider for rustls 0.23, derived from
RustCrypto/rustls-rustcrypto v0.0.2-alpha under its MIT licence.

The provider implements TLS 1.3 (`TLS13_CHACHA20_POLY1305_SHA256`) and, with
`tls12`, TLS 1.2 (`TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256`). It
supplies ChaCha20-Poly1305, SHA-256, HMAC, X25519, P-256 and P-384.
Certificate and handshake signature verification supports P-256/P-384 ECDSA
and Ed25519.

Version 0.3.0 uses chacha20poly1305 0.11, digest 0.11, sha2 0.11,
hmac 0.13, p256/p384 0.14, sec1 0.8, pkcs8 0.11, signature 3,
ed25519-dalek/x25519-dalek 3 and rustls-pki-types 1.
System entropy comes from getrandom 0.4 through its fallible `fill` API.
AEAD traits come from `chacha20poly1305::aead`; there are no direct
aead, crypto-common, rand_core or paste dependencies.

There is deliberately no AES and no RSA. Servers that only offer AES suites,
and servers or certificate chains that need RSA signatures, are refused.

Use an explicit provider:

```rust
let provider = std::sync::Arc::new(ps_rustcrypto::provider());
let config = rustls::ClientConfig::builder_with_provider(provider)
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots)
    .with_no_client_auth();
```

The host supplies trust anchors, socket transport, scheduling and deadlines.
This crate creates no threads, channels or network connections.

Changes from upstream:

- Published fork name and caret dependencies.
- Ported to the current RustCrypto generation with major-line carets.
- Replaced paste identifier generation with explicit type names.
- Removed the unused direct webpki dependency and use pki-types algorithm IDs.
- Removed AES-GCM and RSA (verification and signing) entirely.
- Prefer TLS 1.3 suites and advertise only implemented signature schemes.
- Reject non-contributory X25519 exchanges and propagate key-generation
  entropy failures.
- Require uncompressed NIST-curve TLS key shares.
- Reject undersized TLS 1.2 ChaCha20-Poly1305 records before subtraction.
- Correct the TLS 1.2 IV construction.
- Use strict Ed25519 verification.
- Use deterministic ECDSA signing and expose signing-key SPKI for rustls
  certificate/key consistency checks.
- Omit upstream's incomplete QUIC implementation. TLS suites advertise no
  QUIC support.

There is no ring, AWS-LC, OpenSSL, Tokio or C crypto dependency in this
manifest. Resolved dependencies and target-specific implementation paths
must still be audited before publication.

AES, RSA, P-521, SHA-1 signatures, QUIC and FIPS certification are not
supported. Unsupported algorithms fail verification; they do not
fall back to another provider.
