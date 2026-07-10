<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Signature\Key;

use RoundlyConsulting\Crypto\Random\Bytes;
use RoundlyConsulting\Crypto\Signature\KeyLoadException;
use RoundlyConsulting\Crypto\Signature\WeakKeyException;
use SensitiveParameter;

/**
 * A validated shared secret for HS-family (HMAC) signatures.
 *
 * Four defences live in the factory: an empty secret is rejected; a value that
 * looks like a PEM is rejected so an RSA public key can never be smuggled in as
 * an HMAC key (the classic RS256→HS256 confusion attack); a secret under 256
 * bits is rejected as brute-forceable (RFC 7518 §3.2 requires HS256 keys of at
 * least the hash size); and a single-repeated-byte secret is rejected as
 * obviously low-entropy. The length guard measures bytes, not entropy, so the
 * value MUST be at least 32 *random* bytes.
 */
final readonly class HmacSecret
{
    use ReadsKeyMaterial;

    private const int MIN_BYTES = 32;

    private function __construct(public string $value) {}

    /**
     * @throws WeakKeyException
     */
    public static function fromString(#[SensitiveParameter] string $secret): self
    {
        if ($secret === '') {
            throw WeakKeyException::emptySecret();
        }

        if (str_starts_with($secret, '-----BEGIN')) {
            throw WeakKeyException::pemAsSecret();
        }

        if (strlen($secret) < self::MIN_BYTES) {
            throw WeakKeyException::shortSecret();
        }

        // A single distinct byte (e.g. "aaaa…") satisfies the length guard but
        // carries no entropy — reject the most obvious low-entropy input.
        if (strlen(count_chars($secret, 3)) === 1) {
            throw WeakKeyException::lowEntropySecret();
        }

        return new self($secret);
    }

    /**
     * Generate a fresh CSPRNG secret of at least 256 bits.
     *
     * @throws WeakKeyException when fewer than 32 bytes are requested
     */
    public static function generate(int $bytes = self::MIN_BYTES): self
    {
        if ($bytes < self::MIN_BYTES) {
            throw WeakKeyException::shortSecret();
        }

        // The bytes come straight from the CSPRNG, so the fromString entropy
        // guards can be skipped — construct directly to avoid a spurious throw.
        return new self(Bytes::generate($bytes));
    }

    /**
     * Load a secret from a Laravel filesystem disk.
     *
     * @throws KeyLoadException when the file is missing or the disk is unreadable
     * @throws WeakKeyException when the stored secret fails the strength guards
     */
    public static function fromStorage(string $disk, string $path): self
    {
        return self::fromString(self::readFromStorage($disk, $path));
    }

    /**
     * Load a secret from the consumer's own config key.
     *
     * @throws KeyLoadException when the config value is missing, empty, or not a string
     * @throws WeakKeyException when the configured secret fails the strength guards
     */
    public static function fromConfig(string $key): self
    {
        return self::fromString(self::requireConfigString($key, config($key)));
    }

    /**
     * Load a secret from a disk path, generating and persisting a fresh one when
     * the file is missing. An existing-but-invalid secret is never overwritten —
     * it still throws.
     *
     * @throws KeyLoadException when the disk is unreadable
     * @throws WeakKeyException when an existing secret fails the strength guards
     */
    public static function fromStorageOrGenerate(string $disk, string $path, int $bytes = self::MIN_BYTES): self
    {
        if (self::storageHas($disk, $path)) {
            return self::fromStorage($disk, $path);
        }

        $secret = self::generate($bytes);

        self::persistPrivate($disk, $path, $secret->value);

        return $secret;
    }
}
