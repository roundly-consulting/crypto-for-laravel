<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Codec;

use RoundlyConsulting\Crypto\Exceptions\CryptoException;

/**
 * Thrown when a base64url / base32 / hex string is not valid for its codec.
 */
final class InvalidEncodingException extends CryptoException
{
    public static function base64Url(): self
    {
        return new self('The value is not valid, unpadded base64url.');
    }

    public static function base32(string $character): self
    {
        return new self("The value contains a character outside the base32 alphabet: [{$character}].");
    }

    public static function hex(): self
    {
        return new self('The value is not valid hexadecimal.');
    }
}
