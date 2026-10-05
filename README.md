<!-- roundly-hero:start -->
<p align="center">
  <a href="https://roundly-consulting.com/open-source/docs/crypto-for-laravel?utm_source=github&utm_medium=readme&utm_campaign=open-source&utm_content=crypto-for-laravel">
    <img src="https://raw.githubusercontent.com/roundly-consulting/crypto-for-laravel/main/art/hero.png" alt="Cryptographic Primitives for Laravel — Roundly open source" width="100%">
  </a>
</p>
<!-- roundly-hero:end -->

<!-- roundly-badges:start -->
<p align="center">
  <a href="https://packagist.org/packages/roundly-consulting/crypto-for-laravel"><img src="https://img.shields.io/packagist/v/roundly-consulting/crypto-for-laravel?style=flat-square&label=release" alt="Latest release"></a>
  <a href="https://github.com/roundly-consulting/crypto-for-laravel/actions/workflows/run-tests.yml"><img src="https://img.shields.io/github/actions/workflow/status/roundly-consulting/crypto-for-laravel/run-tests.yml?branch=main&style=flat-square&label=tests" alt="Tests"></a>
  <a href="https://github.com/roundly-consulting/crypto-for-laravel/actions/workflows/fix-php-code-style-issues.yml"><img src="https://img.shields.io/github/actions/workflow/status/roundly-consulting/crypto-for-laravel/fix-php-code-style-issues.yml?branch=main&style=flat-square&label=code%20style" alt="Code style"></a>
  <a href="https://donate.stripe.com/dRmeVe8FX5PF1Qd9pXcEw00"><img src="https://img.shields.io/badge/donate-support%20our%20open%20source-F24E29?style=flat-square&logo=stripe&logoColor=white" alt="Donate"></a>
  <a href="https://www.patreon.com/cw/roundly"><img src="https://img.shields.io/badge/patreon-become%20a%20patron-F96854?style=flat-square&logo=patreon&logoColor=white" alt="Patreon"></a>
  <a href="https://roundly-consulting.com/support-us?utm_source=github&utm_medium=readme&utm_campaign=open-source&utm_content=crypto-for-laravel#crypto"><img src="https://img.shields.io/badge/crypto-BTC%20%C2%B7%20ETH%20%C2%B7%20BNB%20%C2%B7%20SOL-F7931A?style=flat-square&logo=bitcoin&logoColor=white" alt="Crypto"></a>
</p>
<!-- roundly-badges:end -->

# Cryptographic Primitives for Laravel

Native cryptographic and encoding primitives for Laravel — JWS/JOSE and JWK, TOTP/HOTP, WebAuthn
signature verification, HMAC, AES-256-GCM authenticated encryption, X.509, CSPRNG tokens and
codecs — with zero third-party crypto dependencies. It is zero-config: every key is an explicit
argument, and every primitive works on its own.

## Installation

Requires PHP 8.4 (`ext-openssl`, `ext-hash`, `ext-mbstring`; `ext-sodium` for Ed25519), Laravel 12
or 13.

```bash
composer require roundly-consulting/crypto-for-laravel
```

## Usage

Sign and verify a token — the algorithm is always pinned, never read from the token:

```php
use RoundlyConsulting\Crypto\Facades\Crypto;
use RoundlyConsulting\Crypto\Signature\Algorithm;

$key = Crypto::keys()->ec()->fromStorageOrGenerate('local', 'keys/jwt.pem'); // P-256, created on first boot

$token = Crypto::jws()->sign(
    ['kid' => 'k1'],
    ['sub' => 'alice', 'exp' => now()->addHour()->timestamp],
    Crypto::es($key),
);

$claims = Crypto::jws()->verify($token, Crypto::es($key), Algorithm::ES256);
$claims->assertTemporal(leeway: 30);   // throws once expired
$claims->string('sub');                // "alice"
```

Check a webhook, encrypt a value bound to its record, and verify a one-time password:

```php
$expected = 'sha256='.Crypto::hmac()->signHex($request->getContent(), $webhookSecret);
Crypto::constantTimeEquals($expected, $request->header('X-Hub-Signature-256', ''));

$dataKey = Crypto::randomBytes(32);
$sealed = Crypto::aes256Gcm()->seal($dataKey, $iban, associatedData: 'invoices:42');
$iban = Crypto::aes256Gcm()->open($dataKey, $sealed, associatedData: 'invoices:42');

$secret = Crypto::randomSecret();      // base32, for an authenticator app
Crypto::provisioningUri($secret, 'alice@example.com', 'Acme Inc');
Crypto::totp()->verify($secret, $code); // the matched time step, or false
```

<!-- roundly-docs:start -->
## Documentation

The full documentation — configuration, every feature and its API, and testing — lives on our
website: **[roundly-consulting.com/open-source/docs/crypto-for-laravel](https://roundly-consulting.com/open-source/docs/crypto-for-laravel?utm_source=github&utm_medium=readme&utm_campaign=open-source&utm_content=crypto-for-laravel)**

Release notes are in [CHANGELOG.md](CHANGELOG.md). To contribute, see the
[contributing guide](https://github.com/roundly-consulting/.github/blob/main/CONTRIBUTING.md).
<!-- roundly-docs:end -->

<!-- roundly-support:start -->
## Support our work

This package is free and open source, built and maintained by
[Roundly Consulting](https://roundly-consulting.com/open-source?utm_source=github&utm_medium=readme&utm_campaign=open-source&utm_content=crypto-for-laravel).
If it saves you time, please consider supporting our open-source work — a one-time donation, a
monthly pledge on Patreon or a crypto donation helps fund maintenance, new features and new
packages.

<a href="https://donate.stripe.com/dRmeVe8FX5PF1Qd9pXcEw00"><img src="https://img.shields.io/badge/Donate-Support%20Roundly%20open%20source-F24E29?style=for-the-badge&logo=stripe&logoColor=white" alt="Donate to Roundly open source"></a>
<a href="https://www.patreon.com/cw/roundly"><img src="https://img.shields.io/badge/Patreon-Become%20a%20patron-F96854?style=for-the-badge&logo=patreon&logoColor=white" alt="Become a patron on Patreon"></a>
<a href="https://roundly-consulting.com/support-us?utm_source=github&utm_medium=readme&utm_campaign=open-source&utm_content=crypto-for-laravel#crypto"><img src="https://img.shields.io/badge/Crypto-BTC%20%C2%B7%20ETH%20%C2%B7%20BNB%20%C2%B7%20SOL-F7931A?style=for-the-badge&logo=bitcoin&logoColor=white" alt="Donate crypto: BTC, ETH, BNB or SOL"></a>
<!-- roundly-support:end -->

## License

The MIT License (MIT). See [LICENSE.md](LICENSE.md).
