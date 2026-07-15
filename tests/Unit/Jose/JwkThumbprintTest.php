<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Codec\Base64Url;
use RoundlyConsulting\Crypto\Hash\HashAlgorithm;
use RoundlyConsulting\Crypto\Jose\Jwk;
use RoundlyConsulting\Crypto\Signature\Key\EcKey;
use RoundlyConsulting\Crypto\Signature\Key\RsaKey;

/*
 * The RFC 7638 canonicalization is wire-critical: an ACME key authorization is
 * `token.thumbprint` (RFC 8555 §8.1), so a one-byte deviation here breaks every
 * challenge — and therefore every certificate issuance — against Let's Encrypt.
 * These vectors are frozen. If one of them changes, the change is the bug.
 */

it('reproduces the RFC 7638 section 3.1 thumbprint', function (): void {
    $jwk = Jwk::fromJson(readFixture('rfc7638-a1.json'));

    expect($jwk->thumbprint())->toBe('NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs');
});

it('reproduces the frozen ACME account thumbprints', function (string $fixture, string $thumbprint): void {
    $pem = keyPem($fixture);

    $key = str_contains($fixture, 'rsa')
        ? RsaKey::private($pem)
        : EcKey::private($pem);

    expect(Jwk::fromPublicKey($key)->thumbprint())->toBe($thumbprint);
})->with([
    ['acme-account-rsa', 'OhZMC3VkAWpZpXknzUYp3bgjYiZmMfM5j8MQ3C7nbtg'],
    ['acme-account-ec', 'DpAbuSaUplaRVIlOVIuqaTx0TmbkHsJ0Ww75jvLVhnQ'],
]);

it('builds an ACME key authorization from the thumbprint', function (): void {
    // RFC 8555 §8.1: the key authorization is `token.thumbprint` verbatim.
    $jwk = Jwk::fromPublicKey(EcKey::private(keyPem('acme-account-ec')));

    expect('tok3n.'.$jwk->thumbprint())
        ->toBe('tok3n.DpAbuSaUplaRVIlOVIuqaTx0TmbkHsJ0Ww75jvLVhnQ');
});

it('canonicalizes required members only, sorted, with no whitespace', function (): void {
    $jwk = Jwk::fromPublicKey(EcKey::private(keyPem('acme-account-ec')))
        ->withKid('ignored')
        ->withUse('sig');

    $canonical = json_encode($jwk->requiredMembers(), JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);

    expect($canonical)->toStartWith('{"crv":"P-256","kty":"EC","x":"')
        ->and($canonical)->not->toContain(' ')
        ->and($canonical)->not->toContain('\\/')
        ->and(array_keys($jwk->requiredMembers()))->toBe(['crv', 'kty', 'x', 'y']);
});

it('never lets an optional member move the thumbprint', function (): void {
    $jwk = Jwk::fromPublicKey(RsaKey::private(keyPem('acme-account-rsa')));

    $decorated = $jwk->withKid('some-key-id')->withAlg(RoundlyConsulting\Crypto\Signature\Algorithm::RS256)->withUse('sig');

    expect($decorated->thumbprint())->toBe($jwk->thumbprint())
        ->and($decorated->toArray())->toHaveKeys(['alg', 'kid', 'use'])
        ->and($decorated->requiredMembers())->toHaveKeys(['e', 'kty', 'n'])
        ->and($decorated->requiredMembers())->not->toHaveKey('kid');
});

it('treats the hash algorithm as a real parameter', function (): void {
    $jwk = Jwk::fromPublicKey(EcKey::private(keyPem('acme-account-ec')));

    expect($jwk->thumbprint(HashAlgorithm::Sha384))->not->toBe($jwk->thumbprint())
        ->and(strlen($jwk->thumbprintRaw(HashAlgorithm::Sha384)))->toBe(48)
        ->and(strlen($jwk->thumbprintRaw()))->toBe(32)
        ->and(Base64Url::encode($jwk->thumbprintRaw()))->toBe($jwk->thumbprint());
});
