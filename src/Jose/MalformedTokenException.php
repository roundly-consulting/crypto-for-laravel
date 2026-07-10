<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Jose;

use RoundlyConsulting\Crypto\Exceptions\CryptoException;

/**
 * Thrown when a compact JWS is structurally invalid: wrong segment count, bad
 * JSON, a non-object header/payload, an oversize token, or an unsupported
 * `crit` header.
 */
final class MalformedTokenException extends CryptoException
{
    public static function make(string $reason): self
    {
        return new self($reason);
    }
}
