<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Signature;

use RoundlyConsulting\Crypto\Exceptions\CryptoException;

/**
 * Thrown when OpenSSL cannot load, parse, or generate a key, or a loaded key is
 * not of the expected type.
 */
final class KeyLoadException extends CryptoException
{
    public static function unreadable(string $kind): self
    {
        return new self("The {$kind} key could not be read.");
    }

    public static function wrongType(string $kind, string $expected): self
    {
        return new self("The {$kind} key is not an {$expected} key.");
    }

    public static function unsupportedCurve(string $curve): self
    {
        return new self("The EC curve [{$curve}] is not supported.");
    }

    public static function missingFile(string $disk, string $path): self
    {
        return new self("No key material was found on disk [{$disk}] at [{$path}].");
    }

    public static function missingConfig(string $key): self
    {
        return new self("Config key [{$key}] holds no key material (missing, empty, or not a string).");
    }

    public static function generationFailed(): self
    {
        return new self('Key generation failed.');
    }

    public static function notPrivate(string $kind): self
    {
        return new self("The {$kind} key is a public key and holds no private material to export.");
    }

    public static function exportFailed(): self
    {
        return new self('The private key could not be exported to PEM.');
    }

    public static function signingFailed(): self
    {
        return new self('The signature could not be produced.');
    }
}
