<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Cose;

use RoundlyConsulting\Crypto\Exceptions\CryptoException;

/**
 * Thrown when CBOR input violates the decoder's limits or format (indefinite
 * lengths, tags, floats, oversized depth, trailing bytes, truncated input, …).
 */
final class MalformedCborException extends CryptoException
{
    public static function make(string $reason): self
    {
        return new self("Malformed CBOR: {$reason}.");
    }
}
