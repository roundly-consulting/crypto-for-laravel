<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Signature\Key\EcKey;
use RoundlyConsulting\Crypto\Signature\Key\HmacSecret;
use RoundlyConsulting\Crypto\Signature\Key\OkpKey;
use RoundlyConsulting\Crypto\Signature\Key\RsaKey;

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

// Strict typing everywhere.
arch('uses strict types')
    ->expect('RoundlyConsulting\Crypto')
    ->toUseStrictTypes();

// No debugging leftovers.
arch()->preset()->php();
