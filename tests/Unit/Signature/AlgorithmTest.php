<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Signature\Algorithm;

it('exposes the full JOSE alg vocabulary', function (): void {
    expect(array_map(fn (Algorithm $a): string => $a->value, Algorithm::cases()))
        ->toBe(['HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512', 'EdDSA']);
});

it('knows which algorithms are HMAC / asymmetric', function (Algorithm $algorithm, bool $hmac): void {
    expect($algorithm->isHmac())->toBe($hmac)
        ->and($algorithm->isAsymmetric())->toBe(! $hmac);
})->with([
    'HS256' => [Algorithm::HS256, true],
    'HS384' => [Algorithm::HS384, true],
    'HS512' => [Algorithm::HS512, true],
    'RS256' => [Algorithm::RS256, false],
    'ES384' => [Algorithm::ES384, false],
    'EdDSA' => [Algorithm::EdDSA, false],
]);

it('maps each algorithm to its hash name', function (Algorithm $algorithm, string $hash): void {
    expect($algorithm->hashName())->toBe($hash);
})->with([
    'HS256' => [Algorithm::HS256, 'sha256'],
    'RS384' => [Algorithm::RS384, 'sha384'],
    'ES512' => [Algorithm::ES512, 'sha512'],
    'HS384' => [Algorithm::HS384, 'sha384'],
    'HS512' => [Algorithm::HS512, 'sha512'],
    'RS256' => [Algorithm::RS256, 'sha256'],
    'ES256' => [Algorithm::ES256, 'sha256'],
    'ES384' => [Algorithm::ES384, 'sha384'],
    'RS512' => [Algorithm::RS512, 'sha512'],
    'EdDSA' => [Algorithm::EdDSA, 'sha512'],
]);

it('maps the RSA/ECDSA tiers to the matching OpenSSL constant', function (Algorithm $algorithm, int $constant): void {
    expect($algorithm->opensslAlgorithm())->toBe($constant);
})->with([
    'RS256' => [Algorithm::RS256, OPENSSL_ALGO_SHA256],
    'RS384' => [Algorithm::RS384, OPENSSL_ALGO_SHA384],
    'RS512' => [Algorithm::RS512, OPENSSL_ALGO_SHA512],
    'ES256' => [Algorithm::ES256, OPENSSL_ALGO_SHA256],
    'ES384' => [Algorithm::ES384, OPENSSL_ALGO_SHA384],
    'ES512' => [Algorithm::ES512, OPENSSL_ALGO_SHA512],
]);
