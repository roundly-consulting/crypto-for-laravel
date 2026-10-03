# Changelog

All notable changes to `crypto-for-laravel` are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## Unreleased

Initial public release.

### Added

- JWS / JOSE compact and flattened signing with strict verification: HS256/384/512,
  RS256/384/512, ES256/384/512 and EdDSA (Ed25519).
- JWK (RFC 7517) public-key serialization both ways, with RFC 7638 thumbprints and a strict parser.
- X.509 certificate and chain primitives — fingerprints, subject/issuer/SAN, validity dates,
  public keys, extensions, `x5c` / PEM / DER — plus a strict, bounded ASN.1 / DER decoder.
- HOTP and TOTP one-time passwords (RFC 4226 / RFC 6238) on a native base32 codec.
- WebAuthn support: COSE key parsing (P-256/384/521, RSA, Ed25519), a defensive CBOR decoder and
  signature verification.
- HMAC signing and verification, deterministic digests with an optional pepper, and
  constant-time comparisons.
- Authenticated encryption, RFC 5116 `AEAD_AES_256_GCM` (`Aead\Aes256Gcm`, `Crypto::aes256Gcm()`):
  associated data binds a ciphertext to its context; proven against the GCM specification's
  AES-256 vectors and Wycheproof's AES-256-GCM corpus.
- CSPRNG helpers for random bytes, URL-safe / numeric / alphanumeric tokens and base32 secrets.
- Strict codecs: base64url, standard padded base64, base32 and hex.
- Key classes (`HmacSecret`, `RsaKey`, `EcKey`, `OkpKey`) with validated loaders from a
  filesystem disk or your own config key, plus key generators.
- A `Crypto` facade fronting the whole toolbox; every primitive also works on its own, with no
  config file and no env keys — keys are always explicit arguments.
- Facade sub-accessors, so the facade can build every key its own signers take:
  `Crypto::keys()->rsa()` / `ec()` / `ed25519()` / `hmac()` (load from PEM, disk or your config,
  generate, or generate-and-persist on first boot), `Crypto::random()` (bytes, URL-safe /
  numeric / alphanumeric / custom-alphabet tokens, base32 secrets), `Crypto::x509()` (PEM, DER
  and `x5c` certificates, plus `chain()`) and `Crypto::ecDer()` (ECDSA raw ↔ DER).
- Testing helpers: ephemeral keys, known OTP vectors and opt-in Pest expectations for your suites.
