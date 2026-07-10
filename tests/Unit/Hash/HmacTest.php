<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Hash\HashAlgorithm;
use RoundlyConsulting\Crypto\Hash\Hmac;

it('signs and verifies raw bytes', function (): void {
    $hmac = new Hmac(HashAlgorithm::Sha256);
    $sig = $hmac->sign('payload', 'secret-key');

    expect(strlen($sig))->toBe(32)
        ->and($hmac->verify('payload', $sig, 'secret-key'))->toBeTrue();
});

it('produces the known RFC 4231 SHA-256 test vector', function (): void {
    // RFC 4231 test case 1: key of 20 × 0x0b, data "Hi There".
    $sig = (new Hmac(HashAlgorithm::Sha256))->signHex('Hi There', str_repeat("\x0b", 20));

    expect($sig)->toBe('b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7');
});

it('rejects a tampered signature', function (): void {
    $hmac = new Hmac;
    $sig = $hmac->sign('payload', 'secret-key');

    expect($hmac->verify('payload', $sig, 'wrong-key'))->toBeFalse()
        ->and($hmac->verify('tampered', $sig, 'secret-key'))->toBeFalse();
});

it('matches the GitHub sha256= webhook framing', function (): void {
    $secret = 'It\'s a Secret to Everybody';
    $expected = 'sha256='.(new Hmac)->signHex('Hello, World!', $secret);

    expect($expected)->toBe('sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17');
});

it('honours the configured algorithm', function (): void {
    expect(strlen((new Hmac(HashAlgorithm::Sha512))->sign('x', 'k')))->toBe(64)
        ->and(strlen((new Hmac(HashAlgorithm::Sha1))->sign('x', 'k')))->toBe(20);
});
