<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Random;

/**
 * Cryptographically secure random bytes (CSPRNG) from random_bytes.
 */
final class Bytes
{
    /**
     * A sane upper bound (1 MiB) on a single request. No legitimate key or token
     * needs more; the cap stops a caller who wires the length to untrusted input
     * from self-inflicting a memory/CPU DoS.
     */
    public const int MAXIMUM_LENGTH = 1_048_576;

    /**
     * @throws InvalidLengthException when fewer than one byte, or more than
     *                                {@see self::MAXIMUM_LENGTH}, is requested.
     */
    public static function generate(int $length): string
    {
        if ($length < 1) {
            throw InvalidLengthException::tooShort($length, 1);
        }

        if ($length > self::MAXIMUM_LENGTH) {
            throw InvalidLengthException::tooLong($length, self::MAXIMUM_LENGTH);
        }

        return random_bytes($length);
    }
}
