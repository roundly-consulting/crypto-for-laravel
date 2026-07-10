<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Signature\Key;

use OpenSSLAsymmetricKey;
use RoundlyConsulting\Crypto\Signature\Algorithm;
use RoundlyConsulting\Crypto\Signature\KeyLoadException;
use RoundlyConsulting\Crypto\Signature\OpenSsl;
use RoundlyConsulting\Crypto\Signature\Rs;
use RoundlyConsulting\Crypto\Signature\Verifier;
use RoundlyConsulting\Crypto\Signature\WeakKeyException;
use SensitiveParameter;

/**
 * A validated RSA key for RS256 signing (private) or verification (public).
 *
 * Construction proves the PEM is a real RSA key of at least 2048 bits, so a
 * verifier can never be handed a non-RSA or undersized key — this typing is
 * part of what blocks algorithm confusion.
 */
final readonly class RsaKey implements PublicKey
{
    private const int MIN_BITS = 2048;

    private function __construct(
        public OpenSSLAsymmetricKey $key,
        public bool $isPrivate,
    ) {}

    /**
     * Load an RSA public key from PEM.
     *
     * @throws KeyLoadException|WeakKeyException
     */
    public static function public(string $pem): self
    {
        $key = openssl_pkey_get_public($pem);

        if ($key === false) {
            OpenSsl::drainErrors();

            throw KeyLoadException::unreadable('public');
        }

        self::assertRsaAtLeast2048($key, 'public');

        return new self($key, false);
    }

    /**
     * Load an RSA private key from PEM.
     *
     * @throws KeyLoadException|WeakKeyException
     */
    public static function private(#[SensitiveParameter] string $pem): self
    {
        $key = openssl_pkey_get_private($pem);

        if ($key === false) {
            OpenSsl::drainErrors();

            throw KeyLoadException::unreadable('private');
        }

        self::assertRsaAtLeast2048($key, 'private');

        return new self($key, true);
    }

    /**
     * Build a public key from raw modulus and exponent bytes (as carried in a
     * COSE key or JWK).
     *
     * @throws KeyLoadException|WeakKeyException
     */
    public static function fromModulusExponent(string $modulus, string $exponent): self
    {
        if ($modulus === '' || $exponent === '') {
            throw KeyLoadException::unreadable('public');
        }

        return self::public(Asn1::rsaPublicKeyPem($modulus, $exponent));
    }

    /**
     * Generate a fresh RSA private key.
     *
     * @throws KeyLoadException|WeakKeyException
     */
    public static function generate(int $bits = 2048): self
    {
        if ($bits < self::MIN_BITS) {
            throw WeakKeyException::rsaTooSmall($bits);
        }

        $key = OpenSsl::generateKey([
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
            'private_key_bits' => $bits,
        ]);

        return new self($key, true);
    }

    public function algorithm(): Algorithm
    {
        return Algorithm::RS256;
    }

    public function verifier(): Verifier
    {
        return new Rs($this);
    }

    /**
     * @throws KeyLoadException|WeakKeyException
     */
    private static function assertRsaAtLeast2048(OpenSSLAsymmetricKey $key, string $kind): void
    {
        $details = openssl_pkey_get_details($key);

        if ($details === false) {
            throw KeyLoadException::unreadable($kind);
        }

        if (($details['type'] ?? null) !== OPENSSL_KEYTYPE_RSA) {
            throw KeyLoadException::wrongType($kind, 'RSA');
        }

        $bits = (int) ($details['bits'] ?? 0);

        if ($bits < self::MIN_BITS) {
            throw WeakKeyException::rsaTooSmall($bits);
        }
    }
}
