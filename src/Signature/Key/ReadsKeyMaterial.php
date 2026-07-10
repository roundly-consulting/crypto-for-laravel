<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Signature\Key;

use Illuminate\Support\Facades\Storage;
use RoundlyConsulting\Crypto\Signature\KeyLoadException;

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
     * Read raw key material off a filesystem disk, or fail with a typed error.
     *
     * @throws KeyLoadException when the file is missing or the disk is unreadable
     */
    protected static function readFromStorage(string $disk, string $path): string
    {
        $contents = Storage::disk($disk)->get($path);

        if ($contents === null) {
            throw KeyLoadException::missingFile($disk, $path);
        }

        return $contents;
    }

    /**
     * Assert a value read from the consumer's config is a usable, non-empty
     * string. This never calls `config()`; the read lives in the factory.
     *
     * @throws KeyLoadException when the config value is missing, empty, or not a string
     */
    protected static function requireConfigString(string $key, mixed $value): string
    {
        if (! is_string($value) || $value === '') {
            throw KeyLoadException::missingConfig($key);
        }

        return $value;
    }

    protected static function storageHas(string $disk, string $path): bool
    {
        return Storage::disk($disk)->exists($path);
    }

    /**
     * Persist private key material with restrictive visibility where the disk
     * supports it (0600-style perms on the local driver).
     */
    protected static function persistPrivate(string $disk, string $path, string $contents): void
    {
        Storage::disk($disk)->put($path, $contents, 'private');
    }
}
