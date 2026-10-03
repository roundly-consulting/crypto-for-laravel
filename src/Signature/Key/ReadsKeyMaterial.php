<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Signature\Key;

use Illuminate\Contracts\Filesystem\Filesystem;
use Illuminate\Support\Facades\Storage;
use InvalidArgumentException;
use RoundlyConsulting\Crypto\Signature\KeyLoadException;
use RuntimeException;
use SensitiveParameter;

/**
 * Shared plumbing for the opt-in Laravel loading factories (`fromStorage`,
 * `fromConfig`, `fromStorageOrGenerate`).
 *
 * These helpers deliberately touch Laravel's filesystem — the loaders are a
 * Laravel-native convenience on top of the zero-config core (`fromString` /
 * `generate` still work with no container, no config, no disk). The `config()`
 * read itself is NOT here: it stays inline in each `*FromConfig` factory so the
 * zero-config guard can scope config access precisely to those methods; this
 * trait only validates the value once it has been read.
 */
trait ReadsKeyMaterial
{
    /**
     * Read raw key material off a filesystem disk, or fail with a typed error —
     * whether the disk returns null for a missing file (the default) or throws
     * (a disk configured with `'throw' => true`), and for an unknown disk name.
     *
     * @throws KeyLoadException when the file is missing or the disk is unreadable or unknown
     */
    protected static function readFromStorage(string $disk, string $path): string
    {
        $filesystem = self::disk($disk);

        try {
            $contents = $filesystem->get($path);
        } catch (RuntimeException $e) {
            throw KeyLoadException::missingFile($disk, $path, $e);
        }

        if ($contents === null) {
            throw KeyLoadException::missingFile($disk, $path);
        }

        return $contents;
    }

    /**
     * Assert a value read from the consumer's config is a usable string. A blank
     * value (`''` or whitespace, what a host's `KEY=` gives) is not set, so it is
     * missing like an absent one. This never calls `config()`; the read lives in
     * the factory.
     *
     * @throws KeyLoadException when the config value is missing, blank, or not a string
     */
    protected static function requireConfigString(string $key, mixed $value): string
    {
        if (! is_string($value) || trim($value) === '') {
            throw KeyLoadException::missingConfig($key);
        }

        return $value;
    }

    /**
     * @throws KeyLoadException when the disk is unknown
     */
    protected static function storageHas(string $disk, string $path): bool
    {
        return self::disk($disk)->exists($path);
    }

    /**
     * Persist private key material with restrictive visibility where the disk
     * supports it (0600-style perms on the local driver).
     *
     * NOTE: 'private' visibility is driver-dependent. On the local driver it maps
     * to owner-only file permissions; on some adapters (e.g. certain object
     * stores) it is a coarser ACL or a no-op. Only persist secret key material to
     * a disk you control that is private and local-permission-capable — never a
     * world-readable or publicly-served disk.
     *
     * A write that fails is an error, never a shrug: a generated key that was
     * not persisted would be replaced by a DIFFERENT one on the next boot, and
     * everything signed with this one would stop verifying.
     *
     * @throws KeyLoadException when the disk is unknown or the write fails
     */
    protected static function persistPrivate(string $disk, string $path, #[SensitiveParameter] string $contents): void
    {
        $filesystem = self::disk($disk);

        try {
            $written = $filesystem->put($path, $contents, 'private');
        } catch (RuntimeException $e) {
            throw KeyLoadException::unwritable($disk, $path, $e);
        }

        if ($written === false) {
            throw KeyLoadException::unwritable($disk, $path);
        }
    }

    /**
     * @throws KeyLoadException when no disk of that name is configured
     */
    private static function disk(string $disk): Filesystem
    {
        try {
            return Storage::disk($disk);
        } catch (InvalidArgumentException $e) {
            throw KeyLoadException::unknownDisk($disk, $e);
        }
    }

    /**
     * Best-effort in-place wipe of a raw secret string when ext-sodium is
     * available. Passed by reference so the caller's own buffer is zeroed; PHP
     * cannot guarantee wiping (copy-on-write may leave other copies), so this is
     * defence-in-depth, not a guarantee.
     */
    protected static function wipeSecret(#[SensitiveParameter] string &$secret): void
    {
        if (! function_exists('sodium_memzero')) {
            return;
        }

        // Called through a plain callable so the wipe operates on our own buffer
        // without leaking sodium_memzero's "variable becomes null" semantics into
        // the non-nullable secret properties this zeroes.
        /** @var callable(string): void $memzero */
        $memzero = 'sodium_memzero';
        $memzero($secret);
    }
}
