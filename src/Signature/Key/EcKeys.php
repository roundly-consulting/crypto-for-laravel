<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Signature\Key;

use RoundlyConsulting\Crypto\Signature\KeyLoadException;
use RoundlyConsulting\Crypto\Signature\WeakKeyException;
use SensitiveParameter;

/**
 * `Crypto::keys()->ec()` — the {@see EcKey} factories (P-256, P-384, P-521) as
 * instance methods.
 *
 * Pure delegation: same arguments, same curve checks, same exceptions. Secret
 * inputs keep `#[SensitiveParameter]` so this extra frame never puts a PEM into a
 * stack trace.
 */
final readonly class EcKeys
{
    /**
     * @throws KeyLoadException
     */
    public function public(#[SensitiveParameter] string $pem): EcKey
    {
        return EcKey::public($pem);
    }

    /**
     * @throws KeyLoadException
     */
    public function private(#[SensitiveParameter] string $pem): EcKey
    {
        return EcKey::private($pem);
    }

    /**
     * A public key from raw point coordinates (a COSE key or JWK), each exactly
     * the curve's coordinate length.
     *
     * @throws KeyLoadException|WeakKeyException
     */
    public function fromCoordinates(string $x, string $y, string $curve = 'P-256'): EcKey
    {
        return EcKey::fromCoordinates($x, $y, $curve);
    }

    /**
     * @throws KeyLoadException|WeakKeyException
     */
    public function generate(string $curve = 'P-256'): EcKey
    {
        return EcKey::generate($curve);
    }

    /**
     * @throws KeyLoadException
     */
    public function publicFromStorage(string $disk, string $path): EcKey
    {
        return EcKey::publicFromStorage($disk, $path);
    }

    /**
     * @throws KeyLoadException
     */
    public function privateFromStorage(string $disk, string $path): EcKey
    {
        return EcKey::privateFromStorage($disk, $path);
    }

    /**
     * Reads YOUR config key — the package has none of its own.
     *
     * @throws KeyLoadException
     */
    public function publicFromConfig(string $key): EcKey
    {
        return EcKey::publicFromConfig($key);
    }

    /**
     * Reads YOUR config key — the package has none of its own.
     *
     * @throws KeyLoadException
     */
    public function privateFromConfig(string $key): EcKey
    {
        return EcKey::privateFromConfig($key);
    }

    /**
     * Load the private PEM from a disk, or generate and persist one when the file
     * is missing. An existing-but-invalid file is never overwritten.
     *
     * @throws KeyLoadException|WeakKeyException
     */
    public function fromStorageOrGenerate(string $disk, string $path, string $curve = 'P-256'): EcKey
    {
        return EcKey::fromStorageOrGenerate($disk, $path, $curve);
    }
}
