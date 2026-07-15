<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\X509;

use RoundlyConsulting\Crypto\Exceptions\CryptoException;

/**
 * Thrown when a validity predicate is handed a negative leeway.
 *
 * A negative leeway would *narrow* one bound while *widening* the other, which is
 * always a bug — so it is a programmer error, not a certificate problem.
 */
final class InvalidLeewayException extends CryptoException
{
    public static function negative(int $seconds): self
    {
        return new self("The leeway must be zero or positive seconds; got [{$seconds}].");
    }
}
