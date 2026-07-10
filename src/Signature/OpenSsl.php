<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Signature;

/**
 * Shared OpenSSL housekeeping.
 *
 * @internal
 */
final class OpenSsl
{
    /**
     * Empty the OpenSSL error queue so a later, unrelated call isn't blamed for
     * an error raised (and already handled) here.
     */
    public static function drainErrors(): void
    {
        while (openssl_error_string() !== false) {
            // Intentionally empty: we only need to clear the queue.
        }
    }
}
