<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Cose;

use RoundlyConsulting\Crypto\Exceptions\CryptoException;

/**
 * Thrown for an unknown or unavailable COSE algorithm / key type / curve — or
 * when EdDSA is requested but ext-sodium is not loaded.
 */
final class UnsupportedAlgorithmException extends CryptoException
{
    public static function forId(int $id): self
    {
        return new self("Unsupported COSE algorithm identifier [{$id}].");
    }

    public static function keyType(int $kty): self
    {
        return new self("Unsupported COSE key type [{$kty}].");
    }

    public static function curve(int $crv): self
    {
        return new self("Unsupported COSE curve [{$crv}].");
    }

    public static function sodiumMissing(): self
    {
        return new self('EdDSA verification requires the sodium extension, which is not loaded.');
    }
}
