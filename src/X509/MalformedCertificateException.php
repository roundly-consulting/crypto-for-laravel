<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\X509;

use RoundlyConsulting\Crypto\Exceptions\CryptoException;

/**
 * Thrown when a certificate cannot be read, parsed, exported, or when its public
 * key is of a type this package cannot express.
 */
final class MalformedCertificateException extends CryptoException
{
    public static function unreadable(): self
    {
        return new self('The certificate could not be read; it is not valid PEM or DER.');
    }

    public static function notExactDer(): self
    {
        return new self('The input is not exactly one DER certificate: it carries trailing bytes, or an encoding OpenSSL had to rewrite.');
    }

    public static function unparseable(): self
    {
        return new self('The certificate was read but could not be parsed.');
    }

    public static function unsupportedKeyType(): self
    {
        return new self('The certificate carries a public key type this package does not support; expected RSA or EC.');
    }

    public static function exportFailed(): self
    {
        return new self('The certificate could not be exported.');
    }

    public static function issuanceFailed(): self
    {
        return new self('The certificate could not be issued; OpenSSL refused the request.');
    }

    public static function tooLarge(int $bytes, int $max): self
    {
        return new self("The certificate is {$bytes} bytes, over the {$max}-byte cap.");
    }
}
