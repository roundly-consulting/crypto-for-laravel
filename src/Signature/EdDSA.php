<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Signature;

use RoundlyConsulting\Crypto\Cose\UnsupportedAlgorithmException;
use RoundlyConsulting\Crypto\Signature\Key\OkpKey;

/**
 * EdDSA (Ed25519) signer and verifier via ext-sodium.
 *
 * Verification needs only the public key; signing needs a key carrying the
 * secret half. When sodium is unavailable, both throw
 * {@see UnsupportedAlgorithmException} rather than silently degrading.
 */
final readonly class EdDSA implements Signer, Verifier
{
    private const int SIGNATURE_BYTES = 64;

    public function __construct(private OkpKey $key) {}

    public function algorithm(): Algorithm
    {
        return Algorithm::EdDSA;
    }

    /**
     * @throws UnsupportedAlgorithmException when ext-sodium is not loaded
     * @throws KeyLoadException when the key has no secret half to sign with
     */
    public function sign(string $message): string
    {
        if (! function_exists('sodium_crypto_sign_detached')) {
            throw UnsupportedAlgorithmException::sodiumMissing();
        }

        $secretKey = $this->key->secretKey;

        if ($secretKey === null || $secretKey === '') {
            throw KeyLoadException::signingFailed();
        }

        return sodium_crypto_sign_detached($message, $secretKey);
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
