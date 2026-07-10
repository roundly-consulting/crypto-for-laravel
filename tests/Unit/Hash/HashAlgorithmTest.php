<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Hash\HashAlgorithm;

it('flags SHA-1 as legacy and the SHA-2 family as current', function (HashAlgorithm $algorithm, bool $legacy): void {
    expect($algorithm->isLegacy())->toBe($legacy);
})->with([
    'sha1' => [HashAlgorithm::Sha1, true],
    'sha256' => [HashAlgorithm::Sha256, false],
    'sha384' => [HashAlgorithm::Sha384, false],
    'sha512' => [HashAlgorithm::Sha512, false],
]);

it('exposes the exact hash() algorithm name', function (): void {
    expect(HashAlgorithm::Sha256->value)->toBe('sha256');
});
