<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Signature\Key;

use RoundlyConsulting\Crypto\Signature\KeyLoadException;
use RoundlyConsulting\Crypto\Signature\WeakKeyException;
use SensitiveParameter;

/**
 * `Crypto::keys()->rsa()` — the {@see RsaKey} factories as instance methods.
 *
 * Pure delegation: same arguments, same guards (2048–8192 bits, sane exponent),
 * same exceptions. Secret inputs keep `#[SensitiveParameter]` so this extra frame
 * never puts a PEM into a stack trace.
 */
final readonly class RsaKeys
{
    /**
     * @throws KeyLoadException|WeakKeyException
     */
    public function public(string $pem): RsaKey
    {
        return RsaKey::public($pem);
    }

    /**
     * @throws KeyLoadException|WeakKeyException
     */
    public function private(#[SensitiveParameter] string $pem): RsaKey
    {
        return RsaKey::private($pem);
    }

    /**
     * A public key from raw modulus and exponent bytes (a COSE key or JWK).
     *
     * @throws KeyLoadException|WeakKeyException
     */
    public function fromModulusExponent(string $modulus, string $exponent): RsaKey
    {
        return RsaKey::fromModulusExponent($modulus, $exponent);
    }

    /**
     * @throws KeyLoadException|WeakKeyException
     */
    public function generate(int $bits = 2048): RsaKey
    {
        return RsaKey::generate($bits);
    }

    /**
     * @throws KeyLoadException|WeakKeyException
     */
    public function publicFromStorage(string $disk, string $path): RsaKey
    {
        return RsaKey::publicFromStorage($disk, $path);
    }

    /**
     * @throws KeyLoadException|WeakKeyException
     */
    public function privateFromStorage(string $disk, string $path): RsaKey
    {
        return RsaKey::privateFromStorage($disk, $path);
    }

    /**
     * Reads YOUR config key — the package has none of its own.
     *
     * @throws KeyLoadException|WeakKeyException
     */
    public function publicFromConfig(string $key): RsaKey
    {
        return RsaKey::publicFromConfig($key);
    }

    /**
     * Reads YOUR config key — the package has none of its own.
     *
     * @throws KeyLoadException|WeakKeyException
     */
    public function privateFromConfig(string $key): RsaKey
    {
        return RsaKey::privateFromConfig($key);
    }

    /**
     * Load the private PEM from a disk, or generate and persist one when the file
     * is missing. An existing-but-invalid file is never overwritten.
     *
     * @throws KeyLoadException|WeakKeyException
     */
    public function fromStorageOrGenerate(string $disk, string $path, int $bits = 2048): RsaKey
    {
        return RsaKey::fromStorageOrGenerate($disk, $path, $bits);
    }
}
