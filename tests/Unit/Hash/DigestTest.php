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

it('falls back to a plain hash for a null, empty, or whitespace pepper', function (?string $pepper): void {
    $plain = (new Digest)->hex('data');

    expect((new Digest)->withPepper('data', $pepper))->toBe($plain);
})->with([
    'null' => [null],
    'empty' => [''],
    'whitespace' => ['   '],
]);

it('uses an HMAC when a real pepper is supplied', function (): void {
    $peppered = (new Digest)->withPepper('data', 'pepper');

    expect($peppered)->toBe(hash_hmac('sha256', 'data', 'pepper'))
        ->and($peppered)->not->toBe((new Digest)->hex('data'));
});
