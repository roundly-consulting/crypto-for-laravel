<p align="center">
  <a href="https://roundly-consulting.com/open-source">
    <img src="art/hero.png" alt="Crypto For Laravel — Roundly open source" width="100%">
  </a>
</p>

# Cryptographic Primitives for Laravel

Native, audited cryptographic and encoding primitives for Laravel — JWS/JOSE, TOTP/HOTP,
WebAuthn signature verification, HMAC, CSPRNG tokens, and codecs — with **zero third-party
crypto dependencies**. Every primitive is usable **à la carte**: reach for `Hmac` alone to
check a webhook, `Jws` alone for tokens, or `Totp` alone for one-time passwords, without
pulling in anything else.

- **JOSE / JWS** compact and flattened signing + strict verification across the whole SHA-2
  tier (HS256/384/512, RS256/384/512, ES256/384/512) plus EdDSA (Ed25519).
- **RFC 4226 / RFC 6238** HOTP and TOTP built on `hash_hmac` and a native RFC 4648 base32 codec.
- **WebAuthn** COSE key parsing (P-256/P-384/P-521, RSA, Ed25519), a minimal defensive CBOR
  decoder, and signature verification.
- **HMAC** sign/verify, deterministic digests (with optional pepper), and constant-time compares.
- **CSPRNG** random bytes, URL-safe / numeric / alphanumeric tokens, and base32 secrets.
- **Codecs**: strict base64url, standard padded base64, base32 (RFC 4648), and hex.
- **Testing helpers**: ready-made ephemeral keys and known OTP vectors for consumer suites,
  plus opt-in Pest expectations — with no PHPUnit/Pest runtime dependency.
- **Zero-config**: no config file, no env keys — every key and knob is an explicit argument.

Parity with the RFCs and specs is proven by **committed test vectors** (RFC 4226 Appendix D,
RFC 6238 Appendix B, RFC 4231 HMAC-SHA384/512, RFC 7515 Appendix A.1/A.2, RFC 4648, and static
ES256/384/512 / RS256 / EdDSA COSE fixtures) — no external JOSE/JWT/TOTP/WebAuthn/CBOR library
is a dependency.

### Algorithm capability matrix

| Algorithm | Key type | Curve / digest | Sign | Verify | Notes |
|---|---|---|---|---|---|
| HS256 / HS384 / HS512 | `HmacSecret` | SHA-256/384/512 | ✅ | ✅ | secret ≥ 32 random bytes |
| RS256 / RS384 / RS512 | `RsaKey` | RSA ≥ 2048, SHA-256/384/512 | ✅ | ✅ | |
| ES256 / ES384 / ES512 | `EcKey` | P-256 / P-384 / P-521 | ✅ | ✅ | curve fixes the digest |
| EdDSA | `OkpKey` | Ed25519 | ✅¹ | ✅¹ | ¹ needs `ext-sodium` |

The `Es` signer/verifier picks its digest and coordinate size from the key's own curve, so
there is no way to mismatch a curve against a tier. `Hs`/`Rs` take the tier as an argument
(`new Hs($secret, Algorithm::HS512)`, `new Rs($key, Algorithm::RS384)`); a verifier constructed
for one tier never verifies another.

**Choosing an algorithm:** prefer **EdDSA** or **ES256** for new asymmetric tokens (small, fast);
use **RS256** for interop with systems that require RSA; use **HS256** only when both sides share
a secret. Pin the exact algorithm on `verify()` — the package never infers it from the token.

## Requirements

- PHP 8.4+
- Laravel 12 or 13
- Extensions: `ext-openssl`, `ext-hash`, `ext-mbstring` (required); `ext-sodium` (suggested —
  needed only for EdDSA / Ed25519 signing, verification, and key generation; it ships enabled by
  default on modern PHP).
- **Key generation** (`RsaKey::generate()`, `EcKey::generate()`) needs a usable OpenSSL
  configuration (`openssl.cnf`). Loading PEMs, signing, and verifying do not. On a host with a
  missing/broken config, `generate()` throws a typed `Signature\KeyLoadException` rather than
  leaking a PHP warning.

## Installation

```bash
composer require roundly-consulting/crypto-for-laravel
```

That's it. The package auto-registers a minimal, zero-config service provider — **there is no
config file to publish**, no migrations, and nothing to wire. Key material is always passed
explicitly at the call site.

## Design: zero-config, keys are arguments

This package never reads `config()` or `env()`, and never resolves a key from a file or the
container. Every secret, PEM, and OTP secret is a `#[\SensitiveParameter]` argument, and every
behavioural knob (hash algorithm, RSA bits, OTP digits/period) is a constructor default or
named argument. Your application (or another package) owns configuration and wiring; this
package owns the math and encoding.

## Usage

### JWS / JOSE (`Jose\Jws`)

Sign and verify a compact JWS. Verification is deliberately strict: it enforces structure, an
8 KB size cap, a pre-signature algorithm pin (blocking `alg:none` and RS256↔HS256 confusion),
and `crit` rejection — nothing else. Temporal (`exp`/`nbf`/`iat`) checks are opt-in.

```php
use RoundlyConsulting\Crypto\Jose\Jws;
use RoundlyConsulting\Crypto\Signature\Algorithm;
use RoundlyConsulting\Crypto\Signature\Hs;
use RoundlyConsulting\Crypto\Signature\Key\HmacSecret;

$jws = new Jws;
$signer = new Hs(HmacSecret::fromString($secret)); // ≥32 random bytes

$token = $jws->sign(['kid' => 'k1'], ['sub' => 'alice', 'exp' => now()->addHour()->timestamp], $signer);

$claims = $jws->verify($token, $signer, Algorithm::HS256);
$claims->assertTemporal(leeway: 30);   // opt-in: throws if expired / not yet valid
$sub = $claims->string('sub');
```

The RSA and ECDSA tiers work the same way with `Rs`/`Es` and `RsaKey`/`EcKey`. Pick the tier on
the signer (RSA takes it as an argument; ECDSA reads it from the key's curve):

```php
use RoundlyConsulting\Crypto\Signature\Rs;
use RoundlyConsulting\Crypto\Signature\Es;
use RoundlyConsulting\Crypto\Signature\Key\RsaKey;
use RoundlyConsulting\Crypto\Signature\Key\EcKey;

$token  = $jws->sign([], ['sub' => 'bob', 'exp' => $exp], new Rs(RsaKey::private($privatePem), Algorithm::RS512));
$claims = $jws->verify($token, new Rs(RsaKey::public($publicPem), Algorithm::RS512), Algorithm::RS512);

// ES512 on a P-521 key — the curve fixes the digest:
$es = $jws->sign([], ['sub' => 'kim'], new Es(EcKey::private($p521Pem)));
$jws->verify($es, new Es(EcKey::public($p521PublicPem)), Algorithm::ES512);
```

EdDSA (Ed25519) can both sign and verify when `ext-sodium` is present:

```php
use RoundlyConsulting\Crypto\Signature\EdDSA;
use RoundlyConsulting\Crypto\Signature\Key\OkpKey;

$key = OkpKey::generate();                          // or OkpKey::fromSecretKey($sk)
$token = $jws->sign([], ['sub' => 'ed'], new EdDSA($key));
$jws->verify($token, new EdDSA(OkpKey::ed25519($key->publicKey)), Algorithm::EdDSA);
```

Flattened JWS (RFC 7515 §7.2.2, as used by ACME):

```php
$flattened = $jws->flattened(['nonce' => $nonce], $payloadJson, new Rs(RsaKey::private($privatePem)));
$wire = json_encode($flattened); // {"protected":"…","payload":"…","signature":"…"}
```

### HMAC webhooks (`Hash\Hmac`)

```php
use RoundlyConsulting\Crypto\Hash\Hmac;
use RoundlyConsulting\Crypto\Hash\HashAlgorithm;

$hmac = new Hmac(HashAlgorithm::Sha256);

// GitHub-style "sha256=…" header check:
$expected = 'sha256='.$hmac->signHex($request->getContent(), $webhookSecret);
$ok = hash_equals($expected, $request->header('X-Hub-Signature-256', ''));

// Or verify raw signatures directly (constant-time):
$ok = $hmac->verify($payload, $signature, $webhookSecret);
```

### TOTP / HOTP (`Otp\Totp`, `Otp\Hotp`)

```php
use RoundlyConsulting\Crypto\Otp\Totp;
use RoundlyConsulting\Crypto\Otp\ProvisioningUri;
use RoundlyConsulting\Crypto\Random\Secret;

$secret = Secret::base32(32);                     // enrol
$uri = ProvisioningUri::totp($secret, 'alice@example.com', 'Acme Inc');

$totp = new Totp;                                 // SHA1, 6 digits, 30s (default profile)
$code = $totp->codeAt($secret);
$matchedStep = $totp->verify($secret, $userCode); // int|false, timing-flat, drift window
```

Custom profiles use named/positional arguments: `new Totp(OtpAlgorithm::Sha256, digits: 8, period: 60)`.

### WebAuthn signature verification (`Cose\*`, `Signature\KeyVerifier`)

```php
use RoundlyConsulting\Crypto\Cose\AuthenticatorData;
use RoundlyConsulting\Crypto\Cose\CoseKey;
use RoundlyConsulting\Crypto\Cose\CborDecoder;
use RoundlyConsulting\Crypto\Signature\KeyVerifier;

$authData = AuthenticatorData::parse($rawAuthenticatorData);      // rpIdHash, flags, signCount, COSE key
$key = CoseKey::fromDecoded((new CborDecoder)->decode($coseBytes)); // -> a verifiable public key

$ok = (new KeyVerifier)->verify($key, $signedData, $signature);   // ES256 DER or raw, RS256, EdDSA
```

The ceremony (challenge binding, origin, rpId hash, flag policy, sign-count reconciliation)
stays in your relying-party code; this package only decodes bytes and checks signatures.

### CSPRNG (`Random\*`)

```php
use RoundlyConsulting\Crypto\Random\Bytes;
use RoundlyConsulting\Crypto\Random\Token;

$bytes = Bytes::generate(32);
$token = Token::urlSafe(40);                 // base64url, ≥32 chars
$digits = Token::numeric(6);                 // digits only (numeric OTP / recovery code)
$alnum  = Token::alphanumeric(24);           // 0-9A-Za-z
$code   = Token::fromAlphabet('ABCDEFGHJKMNPQRSTUVWXYZ23456789', 10);
```

### Codecs (`Codec\*`)

```php
use RoundlyConsulting\Crypto\Codec\Base64Url;
use RoundlyConsulting\Crypto\Codec\Base64;
use RoundlyConsulting\Crypto\Codec\Base32;
use RoundlyConsulting\Crypto\Codec\Hex;

$encoded = Base64Url::encode($bytes);        // unpadded, URL-safe
$bytes   = Base64Url::decode($encoded);      // STRICT: rejects +, /, =, and non-alphabet

$padded  = Base64::encode($bytes);           // standard padded base64 (+/ alphabet, = padding)
$bytes   = Base64::decode($padded);          // STRICT: rejects non-canonical / non-alphabet
```

### Facade

Prefer facades? `Crypto` fronts the whole toolbox for IDE discoverability — codecs, CSPRNG,
hashing, keyed signers, JOSE, COSE, and OTP. Every factory still takes keys/knobs explicitly and
the manager holds no secret:

```php
use RoundlyConsulting\Crypto\Facades\Crypto;

Crypto::jws()->verify($token, $verifier, Algorithm::RS256);
Crypto::hmac(HashAlgorithm::Sha256)->verify($payload, $sig, $secret);
Crypto::totp(digits: 8)->verify($secret, $code);
Crypto::es(EcKey::public($pem));             // keyed signers via the facade
$t = Crypto::randomToken(40);                // codec/CSPRNG passthroughs return the value
$b = Crypto::base64UrlEncode($bytes);
```

### Testing helpers (`Testing\*`)

Consumer test suites can pull ready-made key material and known OTP vectors instead of
hand-rolling them. These ship in `src/` but import no PHPUnit/Pest symbol:

```php
use RoundlyConsulting\Crypto\Testing\TestKeys;
use RoundlyConsulting\Crypto\Testing\TestOtp;

$secret = TestKeys::hmacSecret();      // a fixed, valid ≥32-byte secret
$rsa    = TestKeys::rsa();             // ephemeral 2048-bit private key
$ec     = TestKeys::ec('P-384');       // ephemeral EC private key
$okp    = TestKeys::ed25519();         // ephemeral Ed25519 (guard on TestKeys::supportsEd25519())

$code = TestOtp::codeAt(time());       // a valid TOTP code for TestOtp::SECRET
```

Optional Pest expectations are shipped as an **opt-in, non-autoloaded** file — `require` it from
your own `tests/Pest.php` (guarded by `function_exists('expect')`, so it never loads at runtime):

```php
// tests/Pest.php
require dirname(__DIR__).'/vendor/roundly-consulting/crypto-for-laravel/src/Testing/pest-expectations.php';

expect($token)->toBeValidJws($verifier, Algorithm::RS256);
expect($code)->toBeValidTotp($secret);
```

## Wiring your own keyed provider

Because this package is zero-config, a keyed signer lives in **your** service provider, built
from **your** config — the crypto package never sees where your key comes from:

```php
use Illuminate\Support\ServiceProvider;
use RoundlyConsulting\Crypto\Signature\Hs;
use RoundlyConsulting\Crypto\Signature\Key\HmacSecret;

final class TokensServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(Hs::class, fn () => new Hs(
            HmacSecret::fromString(config('tokens.secret')),
        ));
    }
}
```

## Exceptions

Everything throws a subtype of `RoundlyConsulting\Crypto\Exceptions\CryptoException`, so you can
catch broadly or precisely and re-wrap at your boundary — e.g.
`Codec\InvalidEncodingException`, `Signature\InvalidSignatureException`,
`Signature\AlgorithmMismatchException`, `Signature\WeakKeyException`,
`Jose\MalformedTokenException`, `Cose\MalformedCborException`,
`Cose\UnsupportedAlgorithmException`, and `Otp\InvalidOtpParameterException`.

## Testing

```bash
composer test
```

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for recent changes.

## License

The MIT License (MIT). See [LICENSE.md](LICENSE.md).
