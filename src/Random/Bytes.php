<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Random;

/**
 * Cryptographically secure random bytes (CSPRNG) from random_bytes.
 */
final class Bytes
{
    /**
     * @throws InvalidLengthException when fewer than one byte is requested.
     */
    public static function generate(int $length): string
    {
        if ($length < 1) {
            throw InvalidLengthException::tooShort($length, 1);
        }

        return random_bytes($length);
    }
}
