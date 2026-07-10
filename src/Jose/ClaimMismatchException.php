<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Jose;

use RoundlyConsulting\Crypto\Exceptions\CryptoException;

/**
 * Thrown by the typed {@see Claims} accessors and the temporal helper when a
 * claim is absent, of the wrong type, or a token is expired / not yet valid.
 */
class ClaimMismatchException extends CryptoException
{
    public static function missing(string $name): self
    {
        return new self("Required claim [{$name}] is missing.");
    }

    public static function notA(string $name, string $type): self
    {
        return new self("Claim [{$name}] is not {$type}.");
    }
}
