<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Cose\CoseAlgorithm;
use RoundlyConsulting\Crypto\Signature\Algorithm;

it('exposes the IANA COSE identifiers', function (): void {
    expect(CoseAlgorithm::ES256->value)->toBe(-7)
        ->and(CoseAlgorithm::EdDSA->value)->toBe(-8)
        ->and(CoseAlgorithm::RS256->value)->toBe(-257);
});

it('maps to the equivalent signature algorithm', function (CoseAlgorithm $cose, Algorithm $signature): void {
    expect($cose->toSignatureAlgorithm())->toBe($signature);
})->with([
    [CoseAlgorithm::ES256, Algorithm::ES256],
    [CoseAlgorithm::EdDSA, Algorithm::EdDSA],
    [CoseAlgorithm::RS256, Algorithm::RS256],
]);
