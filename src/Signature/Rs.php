<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Signature;

use RoundlyConsulting\Crypto\Signature\Key\RsaKey;

/**
 * RSASSA-PKCS1-v1_5 with SHA-256 (RS256) signer and verifier via ext-openssl.
 */
final readonly class Rs implements Signer, Verifier
{
    public function __construct(private RsaKey $key) {}

    public function algorithm(): Algorithm
    {
        return Algorithm::RS256;
    }

    /**
     * @throws KeyLoadException when signing with a public key or OpenSSL fails
     */
    public function sign(string $message): string
    {
        if (! $this->key->isPrivate) {
            throw KeyLoadException::signingFailed();
        }

        $signature = '';

        if (openssl_sign($message, $signature, $this->key->key, OPENSSL_ALGO_SHA256) === false) {
            OpenSsl::drainErrors();

            throw KeyLoadException::signingFailed();
        }

        return $signature;
    }

    public function verify(string $message, string $signature): bool
    {
        // The signature is attacker-controlled, so a malformed one must fail
        // quietly rather than surface a PHP warning. Only an exact 1 passes.
        $result = @openssl_verify($message, $signature, $this->key->key, OPENSSL_ALGO_SHA256);

        if ($result === -1) {
            OpenSsl::drainErrors();
        }

        return $result === 1;
    }
}
