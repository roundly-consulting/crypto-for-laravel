# Changelog

All notable changes to `crypto-for-laravel` are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## Unreleased

### Security

- `ConstantTime::equals()` and `Crypto::constantTimeEquals()` mark the known value
  `#[\SensitiveParameter]` as well as the user value. The expected secret, MAC, token or OTP no
  longer shows up in stack traces, error reports or `debug_backtrace()` output. `Hmac::verify()` and
  `Hs::verify()` also mark the submitted signature.

## 1.0.1 - 2026-10-05

### Changed

- `TestCertificateChain::fingerprints()` and `pinnedFingerprints()` default to SHA-256, like
  `Chain::fingerprints()`. Pass `HashAlgorithm::Sha1` where your verifier pins SHA-1.
- `ProvisioningUri::totp()` (and `Crypto::provisioningUri()`) writes the secret uppercase and
  unpadded. Update any snapshot that pinned a lowercase or padded secret in the URI.
- On a local disk, `fromStorageOrGenerate()` keeps an empty `<key>.lock` file next to the key it
  generates. Leave it in place.
- Maintenance: `composer.json` `homepage` and `support.docs` now point to the documentation site.
- Documentation: the README banner uses an absolute image URL, so it also renders on Packagist and
  other sites.

### Fixed

- Concurrent first boots calling `fromStorageOrGenerate()` (`HmacSecret`, `RsaKey`, `EcKey`,
  `OkpKey`) now share one key: generation runs under a lock, re-checks the disk and returns the key
  read back from it. Before, the last write won and the other processes kept signing with a key
  that was no longer on disk.
- `OkpKey::fromSecretKey()` throws `KeyLoadException` when the secret key's public half does not
  belong to its seed, instead of loading a key whose signatures nothing verifies.
- `Jws::sign()` always encodes the claims as a JSON object. Claims keyed `0, 1, …` used to become a
  JSON array that `verify()` rejected.
- `Chain`, `Chain::fromX5c()` and `Chain::fromPems()` (and `Crypto::x509()->chain()`) throw
  `InvalidChainException` for a gapped or string-keyed array, or an entry of the wrong type,
  instead of failing later with an undefined index or a `TypeError`.
- `ProvisioningUri::totp()` rejects an empty or non-base32 secret instead of building a URI an
  authenticator app enrols but `Totp` can never verify.

### Security

- `Hotp` and `Totp` throw `InvalidOtpParameterException` for a secret that is empty, shorter than
  10 bytes (80 bits) or all zero bytes. Those secrets produced codes anyone could compute. Secrets
  from `Secret::base32()` (160 bits by default) and the common 16-character secrets are unaffected.
- `fromStorageOrGenerate()` on a local disk writes a new key to an owner-only temporary file and
  renames it into place, so the key is never readable by others or half-written, and a failed
  write leaves nothing behind for the next boot to adopt.
- `HmacSecret::fromString()` no longer opens a `file://` path passed in as the secret.
- `HmacSecret::$value` and `OkpKey::$secretKey` are `private(set)`: still readable, but no longer
  writable from outside, so a validated key cannot be swapped for an unchecked one.

## 1.0.0 - 2026-10-03

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
