<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Otp;

use RoundlyConsulting\Crypto\Exceptions\CryptoException;

/**
 * Thrown when an OTP is configured with out-of-range parameters (digits,
 * period, window) or handed a secret that is no usable key.
 */
final class InvalidOtpParameterException extends CryptoException
{
    public static function digits(int $digits): self
    {
        return new self("OTP digits must be between 6 and 10; got [{$digits}].");
    }

    public static function period(int $period): self
    {
        return new self("OTP period must be a positive number of seconds; got [{$period}].");
    }

    public static function window(int $window): self
    {
        return new self("OTP verification window must be between 0 and 10 steps; got [{$window}].");
    }

    public static function shortSecret(int $minimumBytes): self
    {
        $bits = $minimumBytes * 8;

        return new self("OTP secret must decode to at least {$minimumBytes} bytes ({$bits} bits).");
    }

    public static function zeroSecret(): self
    {
        return new self('OTP secret must not be all zero bytes.');
    }

    public static function emptySecret(): self
    {
        return new self('OTP secret must not be empty.');
    }
}
