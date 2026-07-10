<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Signature\Key;

use OpenSSLAsymmetricKey;
use RoundlyConsulting\Crypto\Signature\Algorithm;
use RoundlyConsulting\Crypto\Signature\Es;
use RoundlyConsulting\Crypto\Signature\KeyLoadException;
use RoundlyConsulting\Crypto\Signature\OpenSsl;
use RoundlyConsulting\Crypto\Signature\Verifier;
use RoundlyConsulting\Crypto\Signature\WeakKeyException;
use SensitiveParameter;

/**
 * A validated EC (P-256) key for ES256 signing (private) or verification
 * (public).
 */
final readonly class EcKey implements PublicKey
{
    private const string CURVE = 'P-256';

    private const int COORDINATE_BYTES = 32;

    private function __construct(
        public OpenSSLAsymmetricKey $key,
        public bool $isPrivate,
    ) {}

    /**
     * Load an EC public key from PEM.
     *
     * @throws KeyLoadException
     */
    public static function public(string $pem): self
    {
        $key = openssl_pkey_get_public($pem);

        if ($key === false) {
            OpenSsl::drainErrors();

            throw KeyLoadException::unreadable('public');
        }

        self::assertEc($key, 'public');

        return new self($key, false);
    }

    /**
     * Load an EC private key from PEM.
     *
     * @throws KeyLoadException
     */
    public static function private(#[SensitiveParameter] string $pem): self
    {
        $key = openssl_pkey_get_private($pem);

        if ($key === false) {
            OpenSsl::drainErrors();

            throw KeyLoadException::unreadable('private');
        }

        self::assertEc($key, 'private');

        return new self($key, true);
    }

    /**
     * Build a public key from raw P-256 point coordinates (as carried in a COSE
     * key or JWK).
     *
     * @throws KeyLoadException|WeakKeyException
     */
    public static function fromCoordinates(string $x, string $y, string $curve = self::CURVE): self
    {
        if ($curve !== self::CURVE) {
            throw WeakKeyException::unsupportedCurve($curve);
        }

        if (strlen($x) !== self::COORDINATE_BYTES || strlen($y) !== self::COORDINATE_BYTES) {
            throw KeyLoadException::unreadable('public');
        }

        return self::public(Asn1::ecPublicKeyPem("\x04".$x.$y));
    }

    /**
     * Generate a fresh EC private key on the P-256 curve.
     *
     * @throws KeyLoadException|WeakKeyException
     */
    public static function generate(string $curve = self::CURVE): self
    {
        if ($curve !== self::CURVE) {
            throw WeakKeyException::unsupportedCurve($curve);
        }

        $key = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => 'prime256v1',
        ]);

        if ($key === false) {
            OpenSsl::drainErrors();

            throw KeyLoadException::generationFailed();
        }

        return new self($key, true);
    }

    public function algorithm(): Algorithm
    {
        return Algorithm::ES256;
    }

    public function verifier(): Verifier
    {
        return new Es($this);
    }

    /**
     * @throws KeyLoadException
     */
    private static function assertEc(OpenSSLAsymmetricKey $key, string $kind): void
    {
        $details = openssl_pkey_get_details($key);

        if ($details === false || ($details['type'] ?? null) !== OPENSSL_KEYTYPE_EC) {
            throw KeyLoadException::wrongType($kind, 'EC');
        }
    }
}
