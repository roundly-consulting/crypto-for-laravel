<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Testing;

use RoundlyConsulting\Crypto\Otp\OtpAlgorithm;
use RoundlyConsulting\Crypto\Otp\Totp;

/**
 * A known OTP secret plus matching codes, so a consuming package can assert its
 * TOTP flow against a fixed vector instead of inventing its own.
 */
final class TestOtp
{
    /**
     * A fixed base32 shared secret (never use in production).
     */
    public const string SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

    /**
     * The valid TOTP code for {@see self::SECRET} at the given Unix timestamp,
     * with the default SHA-1 / 6-digit / 30-second parameters.
     */
    public static function codeAt(int $timestamp): string
    {
        return (new Totp(OtpAlgorithm::Sha1, 6, 30))->codeAt(self::SECRET, $timestamp);
    }
}
