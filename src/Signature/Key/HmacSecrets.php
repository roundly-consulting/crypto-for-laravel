<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Signature\Key;

use RoundlyConsulting\Crypto\Signature\KeyLoadException;
use RoundlyConsulting\Crypto\Signature\WeakKeyException;
use SensitiveParameter;

/**
 * `Crypto::keys()->hmac()` — the {@see HmacSecret} factories as instance methods.
 *
 * Pure delegation: the four factory defences (empty, key-material-as-secret,
 * under 256 bits, single repeated byte) run exactly as they do on the static
 * factory. The secret keeps `#[SensitiveParameter]` through this extra frame.
 */
final readonly class HmacSecrets
{
    /**
     * @throws WeakKeyException
     */
    public function fromString(#[SensitiveParameter] string $secret): HmacSecret
    {
        return HmacSecret::fromString($secret);
    }

    /**
     * A fresh CSPRNG secret of at least 256 bits.
     *
     * @throws WeakKeyException when fewer than 32 bytes are requested
     */
    public function generate(int $bytes = 32): HmacSecret
    {
        return HmacSecret::generate($bytes);
    }

    /**
     * @throws KeyLoadException when the file is missing or the disk is unreadable
     * @throws WeakKeyException when the stored secret fails the strength guards
     */
    public function fromStorage(string $disk, string $path): HmacSecret
    {
        return HmacSecret::fromStorage($disk, $path);
    }

    /**
     * Reads YOUR config key — the package has none of its own.
     *
     * @throws KeyLoadException when the config value is missing, blank, or not a string
     * @throws WeakKeyException when the configured secret fails the strength guards
     */
    public function fromConfig(string $key): HmacSecret
    {
        return HmacSecret::fromConfig($key);
    }

    /**
     * Load a secret from a disk, or generate and persist one when the file is
     * missing. An existing-but-invalid secret is never overwritten.
     *
     * @throws KeyLoadException when the disk is unreadable
     * @throws WeakKeyException when an existing secret fails the strength guards
     */
    public function fromStorageOrGenerate(string $disk, string $path, int $bytes = 32): HmacSecret
    {
        return HmacSecret::fromStorageOrGenerate($disk, $path, $bytes);
    }
}
