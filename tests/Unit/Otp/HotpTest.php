<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Codec\Base32;
use RoundlyConsulting\Crypto\Otp\Hotp;
use RoundlyConsulting\Crypto\Otp\InvalidOtpParameterException;
use RoundlyConsulting\Crypto\Otp\OtpAlgorithm;

dataset('rfc4226', [
    [0, '755224'],
    [1, '287082'],
    [2, '359152'],
    [3, '969429'],
    [4, '338314'],
    [5, '254676'],
    [6, '287922'],
    [7, '162583'],
    [8, '399871'],
    [9, '520489'],
]);

it('matches every RFC 4226 Appendix D HOTP vector', function (int $counter, string $expected): void {
    $hotp = new Hotp(OtpAlgorithm::Sha1, 6);
    $secret = Base32::encode('12345678901234567890');

    expect($hotp->at($secret, $counter))->toBe($expected);
})->with('rfc4226');

it('produces the full digit range without 32-bit overflow', function (int $digits, string $expected): void {
    $hotp = new Hotp(OtpAlgorithm::Sha1, $digits);
    $secret = Base32::encode('12345678901234567890');

    // The truncated value for counter 0 is 1_284_755_224; every digit width is a
    // suffix of it, and 10 digits must not overflow a 32-bit int (10^10 does).
    expect($hotp->at($secret, 0))->toBe($expected)
        ->and(strlen($hotp->at($secret, 0)))->toBe($digits);
})->with([
    [6, '755224'],
    [9, '284755224'],
    [10, '1284755224'],
]);

it('exposes its configured digits and algorithm', function (): void {
    $hotp = new Hotp(OtpAlgorithm::Sha256, 8);

    expect($hotp->digits())->toBe(8)
        ->and($hotp->algorithm())->toBe(OtpAlgorithm::Sha256);
});

it('rejects an out-of-range digit count', function (int $digits): void {
    new Hotp(OtpAlgorithm::Sha1, $digits);
})->throws(InvalidOtpParameterException::class)->with([[5], [11]]);

/*
 * HMAC zero-pads a short key, so an empty key and every all-zero key give the
 * same, publicly computable codes. A secret must be real key material: at least
 * 10 bytes (80 bits — the 16-character secrets authenticator apps have issued
 * for years) and never all zero bytes.
 */
it('refuses a secret that decodes to no usable key', function (string $secret, string $reason): void {
    expect(fn (): string => (new Hotp)->at($secret, 1))
        ->toThrow(InvalidOtpParameterException::class, $reason);
})->with([
    'empty' => ['', 'must not be empty'],
    'one zero byte' => ['AA', 'at least 10 bytes (80 bits)'],
    'one zero byte, padded' => ['AA======', 'at least 10 bytes (80 bits)'],
    'nine bytes' => [Base32::encode('123456789'), 'at least 10 bytes (80 bits)'],
    'all zero bytes' => [Base32::encode(str_repeat("\0", 20)), 'must not be all zero bytes'],
]);

it('accepts an 80-bit secret, the floor', function (): void {
    expect((new Hotp)->at(Base32::encode('1234567890'), 1))->toMatch('/^\d{6}$/');
});
