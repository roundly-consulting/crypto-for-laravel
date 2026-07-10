<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Signature;

use RoundlyConsulting\Crypto\Cose\UnsupportedAlgorithmException;
use RoundlyConsulting\Crypto\Signature\Key\OkpKey;

/**
 * EdDSA (Ed25519) signature verification via ext-sodium.
 *
 * Verification only: signing is intentionally out of scope (see the package's
 * sodium-optional posture). When sodium is unavailable, verification throws
 * {@see UnsupportedAlgorithmException} rather than silently passing.
 */
final readonly class EdDSA implements Verifier
{
    private const int SIGNATURE_BYTES = 64;

    public function __construct(private OkpKey $key) {}

    public function algorithm(): Algorithm
    {
        return Algorithm::EdDSA;
    }

    /**
     * @throws UnsupportedAlgorithmException when ext-sodium is not loaded
     */
    public function verify(string $message, string $signature): bool
    {
        if (! function_exists('sodium_crypto_sign_verify_detached')) {
            throw UnsupportedAlgorithmException::sodiumMissing();
        }

        if (strlen($signature) !== self::SIGNATURE_BYTES) {
            return false;
        }

        return sodium_crypto_sign_verify_detached($signature, $message, $this->key->publicKey);
    }
}
