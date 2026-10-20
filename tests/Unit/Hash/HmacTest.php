<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Facades\Crypto;
use RoundlyConsulting\Crypto\Hash\HashAlgorithm;
use RoundlyConsulting\Crypto\Hash\Hmac;
use RoundlyConsulting\Crypto\Signature\WeakKeyException;

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

it('produces the known RFC 4231 SHA-384 and SHA-512 test vectors', function (): void {
    // RFC 4231 test case 1: key of 20 × 0x0b, data "Hi There".
    $key = str_repeat("\x0b", 20);

    expect((new Hmac(HashAlgorithm::Sha384))->signHex('Hi There', $key))
        ->toBe('afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6')
        ->and((new Hmac(HashAlgorithm::Sha512))->signHex('Hi There', $key))
        ->toBe('87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854');
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

it('never verifies a MAC forged with the empty key', function (HashAlgorithm $algorithm): void {
    // Anyone can compute a MAC under the empty key, so a blank configured webhook
    // secret must refuse every signature instead of accepting a forgery.
    $forged = hash_hmac($algorithm->value, 'attacker-body', '', true);

    expect((new Hmac($algorithm))->verify('attacker-body', $forged, ''))->toBeFalse()
        ->and(Crypto::hmac($algorithm)->verify('attacker-body', $forged, ''))->toBeFalse()
        ->and((new Hmac($algorithm))->verify('attacker-body', '', ''))->toBeFalse();
})->with(HashAlgorithm::cases());

it('refuses to sign with an empty key', function (string $method): void {
    expect(fn (): string => (new Hmac)->{$method}('payload', ''))
        ->toThrow(WeakKeyException::class, 'The HMAC secret is empty.')
        ->and(fn (): string => Crypto::hmac()->{$method}('payload', ''))
        ->toThrow(WeakKeyException::class, 'The HMAC secret is empty.');
})->with(['sign', 'signHex']);

it('keeps accepting a short non-empty key', function (): void {
    // RFC 4231 test case 2 uses the four-byte key "Jefe": Hmac takes any non-empty
    // key, and only HmacSecret (the HS-family JOSE path) enforces 32 bytes.
    $hmac = new Hmac;

    expect($hmac->signHex('what do ya want for nothing?', 'Jefe'))
        ->toBe('5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843')
        ->and($hmac->verify('x', $hmac->sign('x', 'k'), 'k'))->toBeTrue();
});
