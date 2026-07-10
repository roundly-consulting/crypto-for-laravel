<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Signature;

use RoundlyConsulting\Crypto\Exceptions\CryptoException;

/**
 * Thrown when a signature fails to verify against the message and key.
 */
final class InvalidSignatureException extends CryptoException
{
    public static function make(): self
    {
        return new self('Signature verification failed.');
    }
}
