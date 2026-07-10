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

it('exposes its configured digits and algorithm', function (): void {
    $hotp = new Hotp(OtpAlgorithm::Sha256, 8);

    expect($hotp->digits())->toBe(8)
        ->and($hotp->algorithm())->toBe(OtpAlgorithm::Sha256);
});

it('rejects an out-of-range digit count', function (int $digits): void {
    new Hotp(OtpAlgorithm::Sha1, $digits);
})->throws(InvalidOtpParameterException::class)->with([[5], [11]]);
