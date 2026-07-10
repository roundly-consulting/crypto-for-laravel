<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Testing;

use RoundlyConsulting\Crypto\Signature\Key\EcKey;
use RoundlyConsulting\Crypto\Signature\Key\HmacSecret;
use RoundlyConsulting\Crypto\Signature\Key\OkpKey;
use RoundlyConsulting\Crypto\Signature\Key\RsaKey;

/**
 * Ready-made key material for a consuming package's own test suite, so nobody
 * has to hand-roll throwaway keypairs or a valid HMAC secret.
 *
 * These ship in `src/` (runtime autoload) but pull in no PHPUnit/Pest symbol —
 * they are plain factories over the package's own key types. Use them only in
 * tests; the RSA/EC/Ed25519 factories mint fresh ephemeral keys on each call.
 */
final class TestKeys
{
    /**
     * A fixed, valid 33-byte HMAC secret (never use in production).
     */
    public static function hmacSecret(): HmacSecret
    {
        return HmacSecret::fromString('0123456789abcdef0123456789abcdef!');
    }

    /**
     * A fresh ephemeral RSA private key.
     */
    public static function rsa(int $bits = 2048): RsaKey
    {
        return RsaKey::generate($bits);
    }

    /**
     * A fresh ephemeral EC private key on the given curve (default P-256).
     */
    public static function ec(string $curve = 'P-256'): EcKey
    {
        return EcKey::generate($curve);
    }

    /**
     * A fresh ephemeral Ed25519 signing key.
     *
     * @throws \RoundlyConsulting\Crypto\Cose\UnsupportedAlgorithmException when ext-sodium is absent
     */
    public static function ed25519(): OkpKey
    {
        return OkpKey::generate();
    }

    /**
     * Whether {@see self::ed25519()} can run on this host.
     */
    public static function supportsEd25519(): bool
    {
        return function_exists('sodium_crypto_sign_keypair');
    }
}
