<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Otp\OtpAlgorithm;

it('exposes hash_hmac algorithm names', function (): void {
    expect(OtpAlgorithm::Sha1->value)->toBe('sha1')
        ->and(OtpAlgorithm::Sha256->value)->toBe('sha256')
        ->and(OtpAlgorithm::Sha512->value)->toBe('sha512');
});
