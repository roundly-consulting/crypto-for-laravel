<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Signature;

use OpenSSLAsymmetricKey;

/**
 * Shared OpenSSL gateway.
 *
 * Every openssl_* call the package makes goes through here so the error-queue
 * housekeeping and the "warning becomes a typed exception" contract live in one
 * place: a failed generate/sign yields a {@see KeyLoadException} (never a leaked
 * PHP warning), and an attacker-controlled verify never surfaces a warning
 * either.
 *
 * @internal
 */
final class OpenSsl
{
    /**
     * Generate a fresh private key, turning any OpenSSL failure (e.g. a missing
     * or unusable `openssl.cnf`) into a typed exception rather than a warning.
     *
     * @param  array<string, mixed>  $options
     *
     * @throws KeyLoadException
     */
    public static function generateKey(array $options): OpenSSLAsymmetricKey
    {
        $key = @openssl_pkey_new($options);

        if ($key === false) {
            self::drainErrors();

            throw KeyLoadException::generationFailed();
        }

        return $key;
    }

    /**
     * Export a private key to PEM for persistence, turning any OpenSSL failure
     * (e.g. an unusable `openssl.cnf`) into a typed exception.
     *
     * @throws KeyLoadException
     */
    public static function exportPrivatePem(OpenSSLAsymmetricKey $key): string
    {
        $pem = '';

        if (@openssl_pkey_export($key, $pem) === false) {
            self::drainErrors();

            throw KeyLoadException::exportFailed();
        }

        return $pem;
    }

    /**
     * Produce a signature, throwing on any OpenSSL failure.
     *
     * @throws KeyLoadException
     */
    public static function sign(string $message, OpenSSLAsymmetricKey $key, int $algorithm): string
    {
        $signature = '';

        if (@openssl_sign($message, $signature, $key, $algorithm) === false) {
            self::drainErrors();

            throw KeyLoadException::signingFailed();
        }

        return $signature;
    }

    /**
     * Verify a signature. The signature is attacker-controlled, so a malformed
     * one fails quietly rather than surfacing a PHP warning; only an exact 1
     * passes.
     */
    public static function verify(string $message, string $signature, OpenSSLAsymmetricKey $key, int $algorithm): bool
    {
        $result = @openssl_verify($message, $signature, $key, $algorithm);

        if ($result === -1) {
            self::drainErrors();
        }

        return $result === 1;
    }

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
