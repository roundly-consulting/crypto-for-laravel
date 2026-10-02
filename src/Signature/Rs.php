<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Signature;

use RoundlyConsulting\Crypto\Signature\Key\RsaKey;

/**
 * RSASSA-PKCS1-v1_5 signer and verifier (RS256/RS384/RS512) via ext-openssl.
 *
 * The digest tier is fixed at construction and pinned per call; the key itself
 * is tier-agnostic (any RSA key of at least 2048 bits works with any RS*).
 */
final readonly class Rs implements Signer, Verifier
{
    public function __construct(
        private RsaKey $key,
        private Algorithm $algorithm = Algorithm::RS256,
    ) {
        if (! self::isRsaAlgorithm($algorithm)) {
            throw AlgorithmMismatchException::keyForAlgorithm($algorithm);
        }
    }

    public function algorithm(): Algorithm
    {
        return $this->algorithm;
    }

    /**
     * @throws KeyLoadException when signing with a public key or OpenSSL fails
     */
    public function sign(string $message): string
    {
        if (! $this->key->isPrivate) {
            throw KeyLoadException::signingFailed();
        }

        return OpenSsl::sign($message, $this->key->key, $this->algorithm->opensslAlgorithm());
    }

    public function verify(string $message, string $signature): bool
    {
        return OpenSsl::verify($message, $signature, $this->publicKey()->key, $this->algorithm->opensslAlgorithm());
    }

    /**
     * The key to verify with. ext-openssl will not verify with a private-key
     * handle — it cannot coerce one into the public key `openssl_verify` needs,
     * so the check fails closed — so a private key verifies through its derived
     * public half, the way an EdDSA key always carries one.
     *
     * @throws KeyLoadException|WeakKeyException when the public half cannot be derived
     */
    private function publicKey(): RsaKey
    {
        return $this->key->isPrivate ? RsaKey::public($this->key->publicPem()) : $this->key;
    }

    private static function isRsaAlgorithm(Algorithm $algorithm): bool
    {
        return match ($algorithm) {
            Algorithm::RS256, Algorithm::RS384, Algorithm::RS512 => true,
            default => false,
        };
    }
}
