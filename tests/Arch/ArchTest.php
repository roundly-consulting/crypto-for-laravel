<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Exceptions\CryptoException;
use RoundlyConsulting\Crypto\Jose\ClaimMismatchException;
use RoundlyConsulting\Crypto\Signature\Key\EcKey;
use RoundlyConsulting\Crypto\Signature\Key\HmacSecret;
use RoundlyConsulting\Crypto\Signature\Key\OkpKey;
use RoundlyConsulting\Crypto\Signature\Key\RsaKey;
use RoundlyConsulting\Testing\Arch\ArchPresets;

ArchPresets::strictTypes('RoundlyConsulting\Crypto');

/**
 * Two exemptions, both deliberate extension points: CryptoException, the abstract base
 * every crypto error extends so a host can catch them uniformly, and ClaimMismatchException,
 * which the JOSE layer's more specific claim errors extend.
 */
ArchPresets::finalByDefault('RoundlyConsulting\Crypto')
    ->ignoring([CryptoException::class, ClaimMismatchException::class]);

/**
 * `noLocalCryptoPrimitives` — and this package is the reason the preset exists.
 *
 * The ban's purpose fleet-wide is: do not re-implement a primitive locally, depend on
 * crypto-for-laravel instead. Crypto IS that dependency, so a naive adoption here is
 * either 100% red or 100% exempt, and both are worthless. What makes it bite is pointing
 * it at the boundary that actually matters INSIDE this package:
 *
 *   the primitive layers may call primitives; the protocol layers must DELEGATE to them.
 *
 * Exempted (they legitimately implement the primitives — that is their entire job):
 *
 *   - Hash\        — Digest, Hmac, HashAlgorithm, ConstantTime (hash, hash_hmac, hash_equals)
 *   - Signature\   — the OpenSsl gateway, Algorithm/Hs/EdDSA, and the Key\* loaders
 *   - Codec\       — Base64, Base64Url (base64_encode/decode ARE the codec)
 *   - Random\      — Bytes, Token (random_bytes, random_int)
 *   - Otp\         — Hotp, OtpAlgorithm (RFC 4226 is defined in terms of HMAC)
 *   - X509\        — Certificate, OpenSslX509 (certificate parsing is openssl)
 *   - Testing\     — TestCertificates, a fixture generator
 *   - CryptoServiceProvider — probes `function_exists('sodium_crypto_sign_verify_detached')`
 *     to report EdDSA availability in `about`; a capability probe, not a use.
 *
 * NOT exempted, and this is the point: Jose\, Cose\, Asn1\, CryptoManager and Facades\.
 * They are protocol/decoding layers, and every one of them is primitive-free today —
 * Jose\Jwk computes its RFC 7638 thumbprint through `new Digest($algorithm)` rather than
 * calling `hash()` itself. Verified to bite: a `hash_hmac()` dropped into Jose\Jws goes
 * red. So this guards the real regression — a protocol layer reaching past the primitive
 * layer for convenience, which is how the constant-time and algorithm-confusion guarantees
 * in Hash\ and Signature\ get silently bypassed.
 */
ArchPresets::noLocalCryptoPrimitives('RoundlyConsulting\Crypto')
    ->ignoring([
        'RoundlyConsulting\Crypto\Hash',
        'RoundlyConsulting\Crypto\Signature',
        'RoundlyConsulting\Crypto\Codec',
        'RoundlyConsulting\Crypto\Random',
        'RoundlyConsulting\Crypto\Otp',
        'RoundlyConsulting\Crypto\X509',
        'RoundlyConsulting\Crypto\Testing',
        'RoundlyConsulting\Crypto\CryptoServiceProvider',
    ]);

/**
 * The Dependency Policy as a test — replaces the hand-rolled loop in
 * DependencyPolicyTest.php, which asserted the same regex against the same file. The two
 * genuinely bespoke rules there (ext-sodium stays a suggestion; the latest two Laravel
 * majors keep resolving) have no preset equivalent and are KEPT in that file.
 *
 * No `alsoAllow`: crypto's `require` ships only php/ext/illuminate/roundly. Crypto is NOT
 * the dev-only carve-out — that covers testing-for-laravel alone, whose `require`
 * legitimately holds testbench and pest. If this goes red, the graph is wrong.
 */
ArchPresets::runtimeRequireIsWhitelisted(__DIR__.'/../../composer.json');

ArchPresets::noDebuggingLeftovers();

/**
 * `swappableModelsAreNotFinal` and `modelsResolveThroughSeam` are skipped with cause:
 * crypto ships no Eloquent model, no config file and no `*_model` key, so both halves of
 * each are structurally inert. This is jwt's rejection, on a package with even less
 * surface — not a judgement call to revisit per row.
 */

// Zero-config (§1c, refined): `env()` is banned everywhere; the package never
// reads env for its own behaviour.
arch('never reads env')
    ->expect('RoundlyConsulting\Crypto')
    ->not->toUse('env');

// `config()` is read ONLY by the key classes' `*FromConfig` factories — an
// explicit, consumer-invoked accessor of the CONSUMER's own key. No other class
// may touch config. (The method-level guard in ZeroConfigScanTest asserts it
// even more precisely, down to the individual factory methods.)
arch('reads config only in the key classes')
    ->expect('RoundlyConsulting\Crypto')
    ->not->toUse(['config', 'Illuminate\Config\Repository'])
    ->ignoring([
        HmacSecret::class,
        RsaKey::class,
        EcKey::class,
        OkpKey::class,
    ]);

// No third-party crypto/JOSE/CBOR/WebAuthn library ever enters the package.
arch('bans third-party crypto libraries')
    ->expect([
        'Firebase\JWT',
        'Lcobucci\JWT',
        'Web-Token',
        'Jose\Component',
        'ParagonIE',
        'CBOR',
        'Cose',
        'Webauthn',
        'OTPHP',
        'PragmaRX',
        'Acme',
    ])
    ->not->toBeUsed();
