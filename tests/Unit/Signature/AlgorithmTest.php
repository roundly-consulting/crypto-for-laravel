<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Signature\Algorithm;

it('exposes the JOSE alg names', function (): void {
    expect(Algorithm::HS256->value)->toBe('HS256')
        ->and(Algorithm::RS256->value)->toBe('RS256')
        ->and(Algorithm::ES256->value)->toBe('ES256')
        ->and(Algorithm::EdDSA->value)->toBe('EdDSA');
});

it('knows which algorithms are asymmetric', function (): void {
    expect(Algorithm::HS256->isAsymmetric())->toBeFalse()
        ->and(Algorithm::RS256->isAsymmetric())->toBeTrue()
        ->and(Algorithm::ES256->isAsymmetric())->toBeTrue()
        ->and(Algorithm::EdDSA->isAsymmetric())->toBeTrue();
});
