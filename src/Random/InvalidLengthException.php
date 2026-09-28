<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Random;

use RoundlyConsulting\Crypto\Exceptions\CryptoException;

/**
 * Thrown when a requested random length is out of range (e.g. non-positive, or
 * below a security floor), or a token alphabet is unusable (empty, not UTF-8).
 */
final class InvalidLengthException extends CryptoException
{
    public static function tooShort(int $length, int $minimum): self
    {
        return new self("A length of [{$length}] is below the minimum of [{$minimum}].");
    }

    public static function tooLong(int $length, int $maximum): self
    {
        return new self("A length of [{$length}] is above the maximum of [{$maximum}].");
    }

    public static function emptyAlphabet(): self
    {
        return new self('The alphabet must contain at least one character.');
    }

    public static function alphabetNotUtf8(): self
    {
        return new self('The alphabet must be valid UTF-8 text; its characters are drawn whole.');
    }
}
