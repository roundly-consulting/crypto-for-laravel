<?php

declare(strict_types=1);

// Zero-config (§1c): no class in the package may read runtime config or env.
arch('is zero-config: no config() or env()')
    ->expect('RoundlyConsulting\Crypto')
    ->not->toUse(['config', 'env'])
    ->and('RoundlyConsulting\Crypto')
    ->not->toUse('Illuminate\Config\Repository');

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
