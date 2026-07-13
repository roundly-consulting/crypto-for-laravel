<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Codec\Base64Url;
use RoundlyConsulting\Crypto\Codec\InvalidEncodingException;

it('round-trips random bytes', function (): void {
    foreach (range(1, 40) as $length) {
        $bytes = random_bytes($length);

        expect(Base64Url::decode(Base64Url::encode($bytes)))->toBe($bytes);
    }
});

it('encodes without padding using the url-safe alphabet', function (): void {
    // 0xFB 0xFF encodes to "+/" in standard base64 → "-_" here, no "=".
    expect(Base64Url::encode("\xFB\xFF"))->toBe('-_8');
});

it('decodes the RFC 7515 A.1 example key', function (): void {
    $decoded = Base64Url::decode('AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow');

    expect(strlen($decoded))->toBe(64);
});

it('rejects standard-base64 characters', function (string $bad): void {
    Base64Url::decode($bad);
})->throws(InvalidEncodingException::class)->with([
    'plus' => ['ab+c'],
    'slash' => ['ab/c'],
    'padding' => ['abc='],
    'space' => ['ab c'],
]);

it('rejects an empty string', function (): void {
    Base64Url::decode('');
})->throws(InvalidEncodingException::class);

it('rejects an invalid base64url length', function (): void {
    // A single leftover char can never form a whole base64 group.
    Base64Url::decode('a');
})->throws(InvalidEncodingException::class);

it('rejects non-canonical input whose final character carries non-zero unused bits', function (string $bad): void {
    // Each of these decodes to the same bytes as its canonical sibling; accepting
    // them would make decode() non-injective (e.g. `QR` and `QQ` both → 0x41),
    // which lets a JWS segment or JWK member be re-spelled without changing its
    // decoded value. See the Base64Url decode canonicality guard.
    Base64Url::decode($bad);
})->throws(InvalidEncodingException::class)->with([
    'QR for QQ' => ['QR'],
    'QS for QQ' => ['QS'],
    'trailing two-bit remainder' => ['AB'],
]);

it('is injective — distinct canonical strings never share decoded bytes', function (): void {
    foreach (range(1, 40) as $length) {
        $canonical = Base64Url::encode(random_bytes($length));

        // The canonical encoding decodes and re-encodes to itself, exactly once.
        expect(Base64Url::encode(Base64Url::decode($canonical)))->toBe($canonical);
    }
});
