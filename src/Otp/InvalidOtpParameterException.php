<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Otp;

use RoundlyConsulting\Crypto\Exceptions\CryptoException;

/**
 * Thrown when an OTP is configured with out-of-range parameters (digits or
 * period).
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
        return new self("OTP verification window must not be negative; got [{$window}].");
    }
}
