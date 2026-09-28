<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Signature\Key;

/**
 * The key-material sub-accessor behind `Crypto::keys()`: one loader per key
 * family, so the facade can produce every key its signers take.
 *
 * Each loader only forwards to the key class's own static factories — the
 * validation guards, the typed failures and the persisted formats all stay in
 * `RsaKey`, `EcKey`, `OkpKey` and `HmacSecret`. Nothing is cached: every call
 * returns a fresh key and the accessor holds no material.
 */
final readonly class Keys
{
    public function rsa(): RsaKeys
    {
        return new RsaKeys;
    }

    public function ec(): EcKeys
    {
        return new EcKeys;
    }

    public function ed25519(): Ed25519Keys
    {
        return new Ed25519Keys;
    }

    public function hmac(): HmacSecrets
    {
        return new HmacSecrets;
    }
}
