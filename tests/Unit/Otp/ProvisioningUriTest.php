<?php

declare(strict_types=1);

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
    $uri = ProvisioningUri::totp('SECRET', 'label', 'Issuer', OtpAlgorithm::Sha512, 8, 60);

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
