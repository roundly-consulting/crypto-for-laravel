<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Signature\Key;

use RoundlyConsulting\Crypto\Cose\UnsupportedAlgorithmException;
use RoundlyConsulting\Crypto\Signature\Algorithm;
use RoundlyConsulting\Crypto\Signature\EdDSA;
use RoundlyConsulting\Crypto\Signature\KeyLoadException;
use RoundlyConsulting\Crypto\Signature\Verifier;
use SensitiveParameter;

/**
 * An Octet Key Pair (OKP) key for EdDSA — the raw 32-byte Ed25519 public key for
 * verification, optionally paired with a 64-byte secret key for signing.
 *
 * Only the Ed25519 curve is supported. Signing (and key generation) requires
 * ext-sodium; loading a public key and verifying does not.
 */
final readonly class OkpKey implements PublicKey
{
    private const int ED25519_PUBLIC_BYTES = 32;

    private const int ED25519_SECRET_BYTES = 64;

    /** @var non-empty-string */
    public string $publicKey;

    /** @var non-empty-string|null */
    public ?string $secretKey;

    /**
     * @param  non-empty-string  $publicKey
     * @param  non-empty-string|null  $secretKey
     */
    private function __construct(string $publicKey, #[SensitiveParameter] ?string $secretKey = null)
    {
        $this->publicKey = $publicKey;
        $this->secretKey = $secretKey;
    }

    /**
     * A public-only key from the raw 32-byte Ed25519 public key.
     *
     * @throws KeyLoadException when the key is not exactly 32 bytes
     */
    public static function ed25519(string $rawPublic): self
    {
        if (strlen($rawPublic) !== self::ED25519_PUBLIC_BYTES) {
            throw KeyLoadException::unreadable('Ed25519 public');
        }

        return new self($rawPublic);
    }

    /**
     * A signing key from a 64-byte libsodium Ed25519 secret key; the public half
     * is derived from it.
     *
     * @throws KeyLoadException when the key is not exactly 64 bytes
     * @throws UnsupportedAlgorithmException when ext-sodium is not loaded
     */
    public static function fromSecretKey(#[SensitiveParameter] string $secretKey): self
    {
        self::assertSodium();

        if (strlen($secretKey) !== self::ED25519_SECRET_BYTES) {
            throw KeyLoadException::unreadable('Ed25519 secret');
        }

        return new self(sodium_crypto_sign_publickey_from_secretkey($secretKey), $secretKey);
    }

    /**
     * Generate a fresh Ed25519 signing key.
     *
     * @throws UnsupportedAlgorithmException when ext-sodium is not loaded
     */
    public static function generate(): self
    {
        self::assertSodium();

        $keypair = sodium_crypto_sign_keypair();

        return new self(
            sodium_crypto_sign_publickey($keypair),
            sodium_crypto_sign_secretkey($keypair),
        );
    }

    public function algorithm(): Algorithm
    {
        return Algorithm::EdDSA;
    }

    public function verifier(): Verifier
    {
        return new EdDSA($this);
    }

    /**
     * @throws UnsupportedAlgorithmException when ext-sodium is not loaded
     */
    private static function assertSodium(): void
    {
        if (! function_exists('sodium_crypto_sign_keypair')) {
            throw UnsupportedAlgorithmException::sodiumMissing();
        }
    }
}
