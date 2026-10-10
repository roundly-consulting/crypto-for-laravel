<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Signature\Key;

use RoundlyConsulting\Crypto\Cose\UnsupportedAlgorithmException;
use RoundlyConsulting\Crypto\Hash\ConstantTime;
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
 *
 * When ext-sodium is present the raw secret key is best-effort wiped from memory
 * when the object is destroyed. PHP cannot guarantee wiping, so this is
 * defence-in-depth, not a guarantee. The `secretKey` property is intentionally
 * not `readonly`: a readonly string cannot be zeroed in place. It is
 * `private(set)` instead, so nothing outside can swap in an unchecked key. The
 * public key is not secret and stays readonly.
 */
final class OkpKey implements PublicKey
{
    use ReadsKeyMaterial;

    private const int ED25519_PUBLIC_BYTES = 32;

    private const int ED25519_SECRET_BYTES = 64;

    private const int ED25519_SEED_BYTES = 32;

    /** @var non-empty-string */
    public readonly string $publicKey;

    public private(set) ?string $secretKey;

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
     * Best-effort wipe of the raw Ed25519 secret key when ext-sodium is
     * available. PHP cannot guarantee memory wiping; this only reduces the window
     * the secret lingers. (OpenSSL key handles elsewhere are opaque and cannot be
     * wiped this way.)
     */
    public function __destruct()
    {
        if ($this->secretKey !== null) {
            self::wipeSecret($this->secretKey);
        }
    }

    /**
     * A public-only key from the raw 32-byte Ed25519 public key.
     *
     * The input is `#[SensitiveParameter]`: a private key handed over by mistake
     * stays out of the trace of the exception that refuses it.
     *
     * @throws KeyLoadException when the key is not exactly 32 bytes
     */
    public static function ed25519(#[SensitiveParameter] string $rawPublic): self
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
     * The key is libsodium's seed ‖ public key, and only the seed signs, so the
     * pair is rebuilt from the seed and must reproduce the key exactly: a public
     * half from another seed would load, then sign with a key no verifier holds.
     *
     * @throws KeyLoadException when the key is not exactly 64 bytes, or its public half does not match its seed
     * @throws UnsupportedAlgorithmException when ext-sodium is not loaded
     */
    public static function fromSecretKey(#[SensitiveParameter] string $secretKey): self
    {
        self::assertSodium();

        if (strlen($secretKey) !== self::ED25519_SECRET_BYTES) {
            throw KeyLoadException::unreadable('Ed25519 secret');
        }

        $seed = substr($secretKey, 0, self::ED25519_SEED_BYTES);
        $keypair = sodium_crypto_sign_seed_keypair($seed);
        $rebuilt = sodium_crypto_sign_secretkey($keypair);
        $matches = ConstantTime::equals($rebuilt, $secretKey);

        self::wipeSecret($seed);
        self::wipeSecret($keypair);
        self::wipeSecret($rebuilt);

        if (! $matches) {
            throw KeyLoadException::mismatchedKeyPair('Ed25519');
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

    /**
     * Load a raw 32-byte Ed25519 public key from a Laravel filesystem disk.
     *
     * @throws KeyLoadException when the file is missing or not 32 bytes
     */
    public static function ed25519FromStorage(string $disk, string $path): self
    {
        return self::ed25519(self::readFromStorage($disk, $path));
    }

    /**
     * Load a raw 32-byte Ed25519 public key from the consumer's own config key.
     *
     * @throws KeyLoadException when the config value is missing or not 32 bytes
     */
    public static function ed25519FromConfig(string $key): self
    {
        return self::ed25519(self::requireConfigString($key, config($key)));
    }

    /**
     * Load a 64-byte Ed25519 secret (signing) key from a Laravel filesystem disk.
     *
     * @throws KeyLoadException when the file is missing or not 64 bytes
     * @throws UnsupportedAlgorithmException when ext-sodium is not loaded
     */
    public static function secretKeyFromStorage(string $disk, string $path): self
    {
        return self::fromSecretKey(self::readFromStorage($disk, $path));
    }

    /**
     * Load a 64-byte Ed25519 secret (signing) key from the consumer's config key.
     *
     * @throws KeyLoadException when the config value is missing or not 64 bytes
     * @throws UnsupportedAlgorithmException when ext-sodium is not loaded
     */
    public static function secretKeyFromConfig(string $key): self
    {
        return self::fromSecretKey(self::requireConfigString($key, config($key)));
    }

    /**
     * Load a signing key from a disk path, generating and persisting a fresh one
     * (the raw 64-byte secret key) when the file is missing. An existing-but-
     * invalid key is never overwritten — it still throws. Concurrent first boots
     * all get the one key written to disk.
     *
     * @throws KeyLoadException when the disk is unreadable, the key cannot be locked or written, or an existing secret is malformed
     * @throws UnsupportedAlgorithmException when ext-sodium is not loaded
     */
    public static function fromStorageOrGenerate(string $disk, string $path): self
    {
        return self::fromSecretKey(self::readOrGenerate(
            $disk,
            $path,
            static fn (): string => (string) self::generate()->secretKey,
        ));
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
