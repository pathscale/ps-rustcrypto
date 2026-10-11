# ps-rustcrypto

A synchronous RustCrypto provider for rustls 0.23, derived from
RustCrypto/rustls-rustcrypto v0.0.2-alpha under its MIT licence.

The provider implements TLS 1.3 and, with `tls12`, TLS 1.2. It supplies
AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305, SHA-256, SHA-384, HMAC,
X25519, P-256 and P-384. Certificate and handshake signature verification
supports P-256/P-384 ECDSA, Ed25519, RSA PKCS#1 and RSA-PSS with SHA-2.

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
- Removed the unused direct webpki dependency and use pki-types algorithm IDs.
- Prefer TLS 1.3 suites and advertise only implemented signature schemes.
- Apply rustls-compatible AES-GCM confidentiality limits.
- Reject non-contributory X25519 exchanges and propagate key-generation
  entropy failures.
- Require uncompressed NIST-curve TLS key shares.
- Reject undersized TLS 1.2 ChaCha20-Poly1305 records before subtraction.
- Correct AES traffic-secret variants and TLS 1.2 IV construction.
- Bound RSA verification keys to 2048 through 8192 bits.
- Use strict Ed25519 verification.
- Use deterministic ECDSA signing and expose signing-key SPKI for rustls
  certificate/key consistency checks.
- Omit upstream's incomplete QUIC implementation. TLS suites advertise no
  QUIC support.

There is no ring, AWS-LC, OpenSSL, Tokio or C crypto dependency in this
manifest. Resolved dependencies and target-specific implementation paths
must still be audited before publication.

P-521, SHA-1 signatures, RSA-PSS public-key OIDs, QUIC and FIPS certification
are not supported. Unsupported algorithms fail verification; they do not
fall back to another provider.

