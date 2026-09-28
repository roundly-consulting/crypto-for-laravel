<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Signature\Key;

use RoundlyConsulting\Crypto\Cose\UnsupportedAlgorithmException;
use RoundlyConsulting\Crypto\Signature\KeyLoadException;
use SensitiveParameter;

/**
 * `Crypto::keys()->ed25519()` — the {@see OkpKey} factories under the same
 * public/private vocabulary as the RSA and EC loaders.
 *
 * "Public" is the raw 32-byte Ed25519 public key; "private" is the 64-byte
 * libsodium secret key (signing, and generation, need ext-sodium). Pure
 * delegation to `OkpKey::ed25519()`, `fromSecretKey()`, `ed25519From*()` and
 * `secretKeyFrom*()` — same guards, same exceptions.
 */
final readonly class Ed25519Keys
{
    /**
     * @throws KeyLoadException when the key is not exactly 32 bytes
     */
    public function public(string $rawPublic): OkpKey
    {
        return OkpKey::ed25519($rawPublic);
    }

    /**
     * @throws KeyLoadException when the key is not exactly 64 bytes
     * @throws UnsupportedAlgorithmException when ext-sodium is not loaded
     */
    public function private(#[SensitiveParameter] string $secretKey): OkpKey
    {
        return OkpKey::fromSecretKey($secretKey);
    }

    /**
     * @throws UnsupportedAlgorithmException when ext-sodium is not loaded
     */
    public function generate(): OkpKey
    {
        return OkpKey::generate();
    }

    /**
     * @throws KeyLoadException when the file is missing or not 32 bytes
     */
    public function publicFromStorage(string $disk, string $path): OkpKey
    {
        return OkpKey::ed25519FromStorage($disk, $path);
    }

    /**
     * @throws KeyLoadException when the file is missing or not 64 bytes
     * @throws UnsupportedAlgorithmException when ext-sodium is not loaded
     */
    public function privateFromStorage(string $disk, string $path): OkpKey
    {
        return OkpKey::secretKeyFromStorage($disk, $path);
    }

    /**
     * Reads YOUR config key — the package has none of its own.
     *
     * @throws KeyLoadException when the config value is missing or not 32 bytes
     */
    public function publicFromConfig(string $key): OkpKey
    {
        return OkpKey::ed25519FromConfig($key);
    }

    /**
     * Reads YOUR config key — the package has none of its own.
     *
     * @throws KeyLoadException when the config value is missing or not 64 bytes
     * @throws UnsupportedAlgorithmException when ext-sodium is not loaded
     */
    public function privateFromConfig(string $key): OkpKey
    {
        return OkpKey::secretKeyFromConfig($key);
    }

    /**
     * Load the 64-byte secret key from a disk, or generate and persist one when
     * the file is missing. An existing-but-invalid file is never overwritten.
     *
     * @throws KeyLoadException when the disk is unreadable or an existing secret is malformed
     * @throws UnsupportedAlgorithmException when ext-sodium is not loaded
     */
    public function fromStorageOrGenerate(string $disk, string $path): OkpKey
    {
        return OkpKey::fromStorageOrGenerate($disk, $path);
    }
}
