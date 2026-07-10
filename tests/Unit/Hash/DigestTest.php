<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Hash\Digest;
use RoundlyConsulting\Crypto\Hash\HashAlgorithm;

it('produces a deterministic hex digest', function (): void {
    $digest = new Digest;

    expect($digest->hex('abc'))->toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
        ->and($digest->hex('abc'))->toBe($digest->hex('abc'));
});

it('produces raw bytes of the algorithm length', function (): void {
    expect(strlen((new Digest(HashAlgorithm::Sha256))->raw('x')))->toBe(32)
        ->and(strlen((new Digest(HashAlgorithm::Sha512))->raw('x')))->toBe(64);
});

it('falls back to a plain hash only for an explicit null pepper', function (): void {
    expect((new Digest)->withPepper('data', null))->toBe((new Digest)->hex('data'));
});

it('keys an HMAC with any non-null pepper, verbatim and untrimmed', function (string $pepper): void {
    $plain = (new Digest)->hex('data');
    $peppered = (new Digest)->withPepper('data', $pepper);

    // A whitespace or empty pepper must NOT downgrade to the plain hash — it is
    // used verbatim as the HMAC key, distinct from the unkeyed digest.
    expect($peppered)->toBe(hash_hmac('sha256', 'data', $pepper))
        ->and($peppered)->not->toBe($plain);
})->with([
    'real' => ['pepper'],
    'whitespace' => ['   '],
    'leading-whitespace' => [' pepper '],
]);

it('matches a committed HMAC known-answer vector for a real pepper', function (): void {
    // RFC 4231 test case 2: key "Jefe", data "what do ya want for nothing?".
    expect((new Digest)->withPepper('what do ya want for nothing?', 'Jefe'))
        ->toBe('5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843');
});
