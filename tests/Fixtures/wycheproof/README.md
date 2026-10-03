# Wycheproof vectors (committed fixtures)

Verbatim copies of Project Wycheproof's `testvectors_v1` corpus, used as committed
known-answer fixtures by `tests/Feature/WycheproofTest.php`. They are **test-only** data —
never a runtime dependency.

## Provenance

- Source: <https://github.com/C2SP/wycheproof> — `testvectors_v1/`
- Fetched: 2026-07-10
- Files (unmodified):
  - `ecdsa_secp256r1_sha256.json` — ECDSA P-256 / SHA-256 verify (484 tests)
  - `rsa_signature_2048_sha256.json` — RSA PKCS#1 v1.5 2048-bit / SHA-256 verify (259 tests)
  - `ed25519.json` — Ed25519 verify (150 tests)
  - `aes_gcm_test.json` — AES-GCM (316 tests; fetched 2026-10-03), asserted by
    `tests/Unit/Aead/Aes256GcmTest.php`: the AES-256 / 96-bit nonce / 128-bit tag group
    (39 valid, 27 invalid) — the only key and nonce size the package exposes

Regeneration is a manual, documented one-off: re-download the same paths from upstream.

## How they are asserted

Each vector's `result` is checked against our verifier's accept/reject decision:

- `valid` → we MUST accept.
- `invalid` → we MUST reject (malformed DER, non-minimal length, wrong `r`/`s`, `s ≥ n`,
  small-order or non-canonical points, bit-flips, truncation, …).
- `acceptable` → a lenient/legacy edge (e.g. ECDSA high-`s` malleability, which JOSE/WebAuthn
  do not forbid). We pin **no** expectation here and count it as skipped, because the correct
  answer is policy-dependent.

## Intentionally skipped / out of scope

- **`acceptable`-result vectors** — skipped per above (raw ECDSA is malleable by design; see
  `tests/Unit/Signature/SignersTest.php`).
- **Curves/hashes we do not expose** — only P-256/SHA-256, RSA-2048/SHA-256, and Ed25519 files
  are imported. P-384/P-521 and other RSA sizes share the same code paths (curve/OID and digest
  are data-driven), so a single curve/size file exercises the parser and verifier logic.
- **Key-import edge files** (e.g. RSA `e`, small primes) — covered directly by
  `tests/Unit/Signature/KeysTest.php` (M1: modulus ceiling + exponent validation), not via the
  signature-verify corpus.
