<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Jose;

/**
 * Thrown by {@see Claims::assertTemporal()} when a token's `exp` has passed.
 */
final class TokenExpiredException extends ClaimMismatchException
{
    public static function expired(): self
    {
        return new self('The token has expired.');
    }
}
