<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use RoundlyConsulting\Crypto\Codec\Base32;
use RoundlyConsulting\Crypto\Otp\InvalidOtpParameterException;
use RoundlyConsulting\Crypto\Otp\OtpAlgorithm;
use RoundlyConsulting\Crypto\Otp\Totp;

afterEach(fn () => CarbonImmutable::setTestNow());

/** RFC 6238 Appendix B seeds (repeated ASCII of the right length per algorithm). */
function rfc6238Seed(OtpAlgorithm $algorithm): string
{
    return match ($algorithm) {
        OtpAlgorithm::Sha1 => str_repeat('1234567890', 2),
        OtpAlgorithm::Sha256 => str_repeat('1234567890', 3).'12',
        OtpAlgorithm::Sha512 => str_repeat('1234567890', 6).'1234',
    };
}

dataset('rfc6238', [
    [OtpAlgorithm::Sha1, 59, '94287082'],
    [OtpAlgorithm::Sha256, 59, '46119246'],
    [OtpAlgorithm::Sha512, 59, '90693936'],
    [OtpAlgorithm::Sha1, 1111111109, '07081804'],
    [OtpAlgorithm::Sha256, 1111111109, '68084774'],
    [OtpAlgorithm::Sha512, 1111111109, '25091201'],
    [OtpAlgorithm::Sha1, 1111111111, '14050471'],
    [OtpAlgorithm::Sha256, 1111111111, '67062674'],
    [OtpAlgorithm::Sha512, 1111111111, '99943326'],
    [OtpAlgorithm::Sha1, 1234567890, '89005924'],
    [OtpAlgorithm::Sha256, 1234567890, '91819424'],
    [OtpAlgorithm::Sha512, 1234567890, '93441116'],
    [OtpAlgorithm::Sha1, 2000000000, '69279037'],
    [OtpAlgorithm::Sha256, 2000000000, '90698825'],
    [OtpAlgorithm::Sha512, 2000000000, '38618901'],
    [OtpAlgorithm::Sha1, 20000000000, '65353130'],
    [OtpAlgorithm::Sha256, 20000000000, '77737706'],
    [OtpAlgorithm::Sha512, 20000000000, '47863826'],
]);

it('matches every RFC 6238 Appendix B TOTP vector', function (OtpAlgorithm $algorithm, int $timestamp, string $expected): void {
    $totp = new Totp($algorithm, 8, 30);
    $secret = Base32::encode(rfc6238Seed($algorithm));

    expect($totp->codeAt($secret, $timestamp))->toBe($expected);
})->with('rfc6238');

it('reproduces every committed TOTP parity vector', function (): void {
    $totp = new Totp(OtpAlgorithm::Sha1, 6, 30);

    foreach (require __DIR__.'/../../Fixtures/totp-parity.php' as [$secret, $timestamp, $expected]) {
        expect($totp->codeAt($secret, $timestamp))->toBe($expected);
    }
});

it('derives the current code from the mocked clock', function (): void {
    CarbonImmutable::setTestNow(CarbonImmutable::createFromTimestamp(1_600_000_000));
    $totp = new Totp;

    expect($totp->codeAt('JBSWY3DPEHPK3PXP'))->toBe($totp->at('JBSWY3DPEHPK3PXP', $totp->timestepAt(1_600_000_000)));
});

it('verifies a code within the drift window', function (): void {
    $totp = new Totp;
    $secret = 'JBSWY3DPEHPK3PXP';
    $code = $totp->codeAt($secret, 1_000_030);

    // One step earlier, still inside window 1.
    expect($totp->verify($secret, $code, 1, 1_000_000))->toBe(33334)
        ->and($totp->verify($secret, $totp->codeAt($secret, 1_000_000), 1, 1_000_000))->toBe(33333);
});

it('rejects a wrong or malformed code', function (): void {
    $totp = new Totp;

    expect($totp->verify('JBSWY3DPEHPK3PXP', '000000', 1, 1_000_000))->toBeFalse()
        ->and($totp->verify('JBSWY3DPEHPK3PXP', 'abc', 1, 1_000_000))->toBeFalse()
        ->and($totp->verify('JBSWY3DPEHPK3PXP', '12345', 1, 1_000_000))->toBeFalse();
});

it('returns the integer 0 for a match at timestep zero', function (): void {
    $totp = new Totp;
    $secret = 'JBSWY3DPEHPK3PXP';
    $code = $totp->codeAt($secret, 0);

    // A match at timestep 0 must be the int 0, not false — the two are only
    // distinguishable with a strict comparison, which callers must use.
    expect($totp->verify($secret, $code, 0, 0))->toBe(0)
        ->and($totp->verify($secret, $code, 0, 0))->not->toBeFalse();
});

it('rejects a negative verification window', function (): void {
    (new Totp)->verify('JBSWY3DPEHPK3PXP', '000000', -1, 1_000_000);
})->throws(InvalidOtpParameterException::class);

it('rejects a drift window beyond the documented maximum', function (): void {
    (new Totp)->verify('JBSWY3DPEHPK3PXP', '000000', Totp::MAX_WINDOW + 1, 1_000_000);
})->throws(InvalidOtpParameterException::class);

it('accepts the maximum drift window', function (): void {
    // The largest permitted window must be usable, not merely the boundary of a
    // rejection; a match at that extreme still verifies.
    $totp = new Totp;
    $secret = 'JBSWY3DPEHPK3PXP';
    $code = $totp->codeAt($secret, 1_000_000 + Totp::MAX_WINDOW * 30);

    expect($totp->verify($secret, $code, Totp::MAX_WINDOW, 1_000_000))->toBe(33333 + Totp::MAX_WINDOW);
});

it('rejects a non-positive period', function (): void {
    new Totp(OtpAlgorithm::Sha1, 6, 0);
})->throws(InvalidOtpParameterException::class);

it('rejects an out-of-range digit count', function (): void {
    new Totp(OtpAlgorithm::Sha1, 4, 30);
})->throws(InvalidOtpParameterException::class);

it('never verifies a code against an empty secret', function (): void {
    // The code anyone can compute: HMAC over the empty key.
    $hash = hash_hmac('sha1', pack('J', intdiv(1_800_000_000, 30)), '', true);
    $offset = ord($hash[19]) & 0x0F;
    $code = str_pad((string) ((unpack('N', substr($hash, $offset, 4))[1] & 0x7FFFFFFF) % 1_000_000), 6, '0', STR_PAD_LEFT);

    (new Totp)->verify('', $code, 1, 1_800_000_000);
})->throws(InvalidOtpParameterException::class, 'must not be empty');
