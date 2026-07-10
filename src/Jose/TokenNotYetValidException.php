<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Jose;

/**
 * Thrown by {@see Claims::assertTemporal()} when a token's `nbf`/`iat` is in the
 * future.
 */
final class TokenNotYetValidException extends ClaimMismatchException
{
    public static function notYetValid(): self
    {
        return new self('The token is not valid yet (nbf).');
    }

    public static function issuedInFuture(): self
    {
        return new self('The token was issued in the future (iat).');
    }
}
