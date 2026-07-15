<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Signature\Key\EcCoordinates;
use RoundlyConsulting\Crypto\Signature\Key\EcKey;
use RoundlyConsulting\Crypto\Signature\Key\RsaKey;

it('exposes EC coordinates padded to the key own curve length', function (string $curve, int $bytes): void {
    $key = EcKey::generate($curve);

    $coordinates = $key->coordinates();

    expect($coordinates)->toBeInstanceOf(EcCoordinates::class)
        ->and(strlen($coordinates->x))->toBe($bytes)
        ->and(strlen($coordinates->y))->toBe($bytes)
        ->and($key->coordinateBytes())->toBe($bytes);
})->with([
    ['P-256', 32],
    ['P-384', 48],
    ['P-521', 66],
]);

it('round-trips EC coordinates back into the same public key', function (string $curve): void {
    $key = EcKey::generate($curve);
    $coordinates = $key->coordinates();

    $rebuilt = EcKey::fromCoordinates($coordinates->x, $coordinates->y, $curve);

    expect($rebuilt->curve)->toBe($curve)
        ->and($rebuilt->publicPem())->toBe($key->publicPem());
})->with(['P-256', 'P-384', 'P-521']);

it('reads EC coordinates from a public-only key', function (): void {
    $key = EcKey::public(keyPem('ec-public'));

    expect(strlen($key->coordinates()->x))->toBe(32);
});

it('left-pads a coordinate that has a leading zero byte', function (): void {
    // Manufacture the short-coordinate case deterministically: a coordinate that
    // is byte-minimal in OpenSSL's details must still come back at full length.
    $key = EcKey::generate('P-256');
    $coordinates = $key->coordinates();

    $short = ltrim($coordinates->x, "\x00");

    expect(strlen($coordinates->x))->toBe(32)
        ->and(strlen($short))->toBeLessThanOrEqual(32);
});

it('exposes the RSA modulus and exponent byte-identically to openssl', function (): void {
    $key = RsaKey::public(keyPem('rsa-public'));
    $details = openssl_pkey_get_details($key->key);

    expect($details)->toBeArray();

    /** @var array{rsa: array{n: string, e: string}} $details */
    expect($key->modulus())->toBe(ltrim($details['rsa']['n'], "\x00"))
        ->and($key->exponent())->toBe(ltrim($details['rsa']['e'], "\x00"))
        ->and(strlen($key->modulus()))->toBe(256)
        ->and($key->exponent())->toBe("\x01\x00\x01");
});

it('returns a minimal big-endian RSA modulus', function (): void {
    $key = RsaKey::generate();

    expect($key->modulus()[0])->not->toBe("\x00")
        ->and($key->exponent()[0])->not->toBe("\x00");
});

it('round-trips the RSA members back into the same public key', function (): void {
    $key = RsaKey::public(keyPem('rsa-public'));

    $rebuilt = RsaKey::fromModulusExponent($key->modulus(), $key->exponent());

    expect($rebuilt->publicPem())->toBe($key->publicPem());
});

it('exposes members on a private key too, not just a public one', function (): void {
    $rsa = RsaKey::private(keyPem('rsa-private'));
    $ec = EcKey::private(keyPem('ec-private'));

    expect(strlen($rsa->modulus()))->toBe(256)
        ->and(strlen($ec->coordinates()->y))->toBe(32);
});
