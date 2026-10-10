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
 * ONE exemption: ClaimMismatchException, which the JOSE layer's more specific claim errors
 * extend. It is concrete, so `final` on it would be a real breaking change to that hierarchy.
 *
 * `CryptoException::class` is GONE from this list, and its removal is a small finding rather
 * than tidying. It is **abstract**, and `finalByDefault` skips abstract classes on its own
 * (`abstract final` is a PHP fatal, so flagging one was a false positive by construction) —
 * so the entry silenced nothing it needed to. The rot-check cannot catch this class of dead
 * weight either: the class exists, so the entry looks live. It was found by asking what each
 * exemption still buys, which is the same audit metrics ran when it dropped seven abstract
 * bases.
 *
 * The list moved to the `$ignoring` PARAMETER, which buys the two things Pest's fluent
 * `->ignoring()` cannot: rot-checking, and recovery of the prefix SHADOW (Pest matches
 * exemptions by string prefix, not class identity — pest-plugin-arch Blueprint.php:103).
 * Measured across all 69 concrete classes here: this list shadows **nothing**. The package
 * holds exactly one latent prefix pair — `Codec\Base64` over `Codec\Base64Url` — and both
 * are final, so the guard is prospective: it fires the day Base64 is exempted and Base64Url
 * is opened.
 */
ArchPresets::finalByDefault('RoundlyConsulting\Crypto', [
    ClaimMismatchException::class,
]);

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
 *   - Aead\        — Aes256Gcm (openssl_encrypt / openssl_decrypt ARE the AEAD)
 *   - Hash\        — Digest, Hmac, HashAlgorithm, ConstantTime (hash, hash_hmac, hash_equals)
 *   - Signature\   — the OpenSsl gateway, Algorithm/Hs/EdDSA, and the Key\* loaders
 *   - Codec\       — Base64, Base64Url (base64_encode/decode ARE the codec)
 *   - Random\      — Bytes, Token (random_bytes, random_int)
 *   - Otp\         — Hotp, OtpAlgorithm (RFC 4226 is defined in terms of HMAC)
 *   - X509\        — Certificate, OpenSslX509 (certificate parsing is openssl)
 *   - Testing\     — TestCertificates, a fixture generator
 *
 * NOT exempted, and this is the point: Jose\, Cose\, Asn1\, CryptoManager and Facades\.
 * They are protocol/decoding layers, and every one of them is primitive-free today —
 * Jose\Jwk computes its RFC 7638 thumbprint through `new Digest($algorithm)` rather than
 * calling `hash()` itself. Verified to bite: a `hash_hmac()` dropped into Jose\Jws goes
 * red. So this guards the real regression — a protocol layer reaching past the primitive
 * layer for convenience, which is how the constant-time and algorithm-confusion guarantees
 * in Hash\ and Signature\ get silently bypassed.
 *
 * ## CryptoServiceProvider is no longer exempt, and never needed to be
 *
 * It was exempted for `function_exists('sodium_crypto_sign_verify_detached')` — a capability
 * probe reported in `about`, argued (correctly) to be a mention rather than a use. The
 * argument was sound and the exemption was still pointless: the primitive's name appears
 * there only as a **string literal**, and Pest's arch layer resolves symbol usage, not
 * string contents, so the ban never saw it. The exemption silenced a violation that did not
 * exist — which the rot-check cannot detect, since the class is real.
 *
 * The cost was not zero. An exemption is scoped to a CLASS, not a function, so this one
 * blinded the provider to all 19 primitives to excuse a probe that was never flagged.
 * Measured both ways before removing: with a real `random_bytes()` call injected into
 * `register()`, the preset is GREEN with the exemption and RED without it. The provider is
 * wiring — not a primitive layer — so the ban belongs on it, and now holds it.
 *
 * The layer boundary above is unchanged: the seven primitive namespaces stay exempt because
 * implementing primitives is their job.
 */
ArchPresets::noLocalCryptoPrimitives('RoundlyConsulting\Crypto', [
    'RoundlyConsulting\Crypto\Aead',
    'RoundlyConsulting\Crypto\Hash',
    'RoundlyConsulting\Crypto\Signature',
    'RoundlyConsulting\Crypto\Codec',
    'RoundlyConsulting\Crypto\Random',
    'RoundlyConsulting\Crypto\Otp',
    'RoundlyConsulting\Crypto\X509',
    'RoundlyConsulting\Crypto\Testing',
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
 * `modelsGoThroughTheFacade` is skipped with cause: crypto has no `Models`, `Concerns` or
 * `Traits` namespace — no model, no host-facing trait, nothing that could bypass the
 * manager. (`Signature\Key\ReadsKeyMaterial` is loader plumbing shared by the key
 * classes, not a trait a host model uses.)
 *
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
// even more precisely, down to the individual factory methods.) The `Config`
// facade and the injectable contract are the other two doors to the same store.
arch('reads config only in the key classes')
    ->expect('RoundlyConsulting\Crypto')
    ->not->toUse([
        'config',
        'Illuminate\Config\Repository',
        'Illuminate\Contracts\Config\Repository',
        'Illuminate\Support\Facades\Config',
    ])
    ->ignoring([
        HmacSecret::class,
        RsaKey::class,
        EcKey::class,
        OkpKey::class,
    ]);

// No third-party crypto/JOSE/CBOR/WebAuthn library ever enters the package.
//
// A source-token scan, not `->not->toBeUsed()`: Pest's arch layer resolves a name only
// through an installed PSR-4 root at or above it, so it missed sibling packages under a
// vendor prefix (web-token's old split `Jose\Component\Core\…` roots), and every vendor
// that is not installed — the exact case a ban exists for. The preset resolves each name
// through the file's namespace and imports, so a bare vendor prefix covers all its packages.
ArchPresets::noVendorNamespace([
    'Firebase\JWT',
    'Lcobucci\JWT',
    'Jose',
    'ParagonIE',
    'CBOR',
    'Cose',
    'Webauthn',
    'OTPHP',
    'PragmaRX',
], __DIR__.'/../../src');
