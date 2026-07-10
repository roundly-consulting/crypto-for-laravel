<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Signature;

use RoundlyConsulting\Crypto\Exceptions\CryptoException;

/**
 * Thrown when key material is too weak to use safely: an RSA key under 2048
 * bits, an HMAC secret under 256 bits or with no entropy, or an unsupported
 * curve.
 */
final class WeakKeyException extends CryptoException
{
    public static function emptySecret(): self
    {
        return new self('The HMAC secret is empty.');
    }

    public static function pemAsSecret(): self
    {
        return new self('A PEM-encoded key cannot be used as an HMAC secret.');
    }

    public static function shortSecret(): self
    {
        return new self('The HMAC secret must be at least 32 random bytes; generate one with `openssl rand -base64 48`.');
    }

    public static function lowEntropySecret(): self
    {
        return new self('The HMAC secret is a single repeated byte; use at least 32 random bytes.');
    }

    public static function longSecret(): self
    {
        return new self('The HMAC secret must be at most 1024 bytes; a longer key adds no security.');
    }

    public static function rsaTooSmall(int $bits): self
    {
        return new self("The RSA key must be at least 2048 bits; got [{$bits}].");
    }

    public static function rsaTooLarge(int $bits): self
    {
        return new self("The RSA key must be at most 8192 bits; got [{$bits}].");
    }

    public static function rsaBadExponent(): self
    {
        return new self('The RSA public exponent must be an odd integer of at least 3 (65537 is the norm).');
    }

    public static function unsupportedCurve(string $curve): self
    {
        return new self("The curve [{$curve}] is not supported.");
    }
}
