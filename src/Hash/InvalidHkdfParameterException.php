<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Hash;

use RoundlyConsulting\Crypto\Exceptions\CryptoException;

/**
 * Empty input keying material or an output length HKDF cannot produce — a programming
 * error, never a property of the data.
 */
final class InvalidHkdfParameterException extends CryptoException
{
    public static function emptyKeyMaterial(): self
    {
        return new self('The input keying material must not be empty.');
    }

    public static function length(int $length, int $maximum): self
    {
        return new self("A length of [{$length}] is outside 1–{$maximum} bytes (255 × the hash length).");
    }
}
