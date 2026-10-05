<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Codec\InvalidEncodingException;
use RoundlyConsulting\Crypto\Otp\InvalidOtpParameterException;
use RoundlyConsulting\Crypto\Otp\OtpAlgorithm;
use RoundlyConsulting\Crypto\Otp\ProvisioningUri;

it('builds an otpauth totp uri with the issuer as an explicit argument', function (): void {
    $uri = ProvisioningUri::totp('JBSWY3DPEHPK3PXP', 'alice@example.com', 'Acme Inc');

    expect($uri)->toStartWith('otpauth://totp/Acme%20Inc:alice%40example.com?')
        ->and($uri)->toContain('secret=JBSWY3DPEHPK3PXP')
        ->and($uri)->toContain('issuer=Acme%20Inc')
        ->and($uri)->toContain('algorithm=SHA1')
        ->and($uri)->toContain('digits=6')
        ->and($uri)->toContain('period=30');
});

it('reflects a custom algorithm, digits, and period', function (): void {
    $uri = ProvisioningUri::totp('JBSWY3DPEHPK3PXP', 'label', 'Issuer', OtpAlgorithm::Sha512, 8, 60);

    expect($uri)->toContain('algorithm=SHA512')
        ->and($uri)->toContain('digits=8')
        ->and($uri)->toContain('period=60');
});

it('rejects out-of-range digits and period', function (Closure $call): void {
    $call();
})->throws(InvalidOtpParameterException::class)->with([
    'digits' => [fn () => ProvisioningUri::totp('S', 'l', 'i', OtpAlgorithm::Sha1, 4)],
    'period' => [fn () => ProvisioningUri::totp('S', 'l', 'i', OtpAlgorithm::Sha1, 6, 0)],
]);

it('refuses a secret an authenticator would enrol but Totp could never verify', function (string $secret, string $exception, string $reason): void {
    expect(fn (): string => ProvisioningUri::totp($secret, 'alice@example.com', 'Acme'))
        ->toThrow($exception, $reason);
})->with([
    'spaced groups' => ['JBSW Y3DP EHPK 3PXP', InvalidEncodingException::class, '[ ]'],
    'outside the alphabet' => ['JBSWY3DP1HPK3PXP', InvalidEncodingException::class, '[1]'],
    'empty' => ['', InvalidOtpParameterException::class, 'must not be empty'],
]);

it('emits the secret in canonical form: uppercase, unpadded', function (string $secret, string $canonical): void {
    expect(ProvisioningUri::totp($secret, 'alice@example.com', 'Acme'))
        ->toContain('?secret='.$canonical.'&');
})->with([
    'lowercase' => ['jbswy3dpehpk3pxp', 'JBSWY3DPEHPK3PXP'],
    'padded' => ['MZXW6YTBOI======', 'MZXW6YTBOI'],
]);
