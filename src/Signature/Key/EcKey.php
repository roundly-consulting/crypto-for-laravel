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
 * A validated EC key for ECDSA signing (private) or verification (public) on the
 * P-256, P-384, or P-521 curve — i.e. ES256, ES384, and ES512.
 *
 * The curve is detected at load time and drives the coordinate size and the
 * algorithm the key is pinned to, so a caller can never mismatch a curve against
 * a digest tier.
 */
final readonly class EcKey implements PublicKey
{
    private const string DEFAULT_CURVE = 'P-256';

    /**
     * Per-curve parameters: the OpenSSL curve name, the fixed coordinate byte
     * length, the ES* algorithm, and the ASN.1 OID for the SPKI wrapper.
     *
     * @var array<string, array{openssl: string, bytes: int, algorithm: Algorithm, oid: string}>
     */
    private const array CURVES = [
        'P-256' => ['openssl' => 'prime256v1', 'bytes' => 32, 'algorithm' => Algorithm::ES256, 'oid' => "\x06\x08\x2A\x86\x48\xCE\x3D\x03\x01\x07"],
        'P-384' => ['openssl' => 'secp384r1', 'bytes' => 48, 'algorithm' => Algorithm::ES384, 'oid' => "\x06\x05\x2B\x81\x04\x00\x22"],
        'P-521' => ['openssl' => 'secp521r1', 'bytes' => 66, 'algorithm' => Algorithm::ES512, 'oid' => "\x06\x05\x2B\x81\x04\x00\x23"],
    ];

    /**
     * OpenSSL curve name → our curve label, for detecting a loaded key's curve.
     *
     * @var array<string, string>
     */
    private const array OPENSSL_CURVES = [
        'prime256v1' => 'P-256',
        'secp384r1' => 'P-384',
        'secp521r1' => 'P-521',
    ];

    private function __construct(
        public OpenSSLAsymmetricKey $key,
        public bool $isPrivate,
        public string $curve,
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

        return new self($key, false, self::detectCurve($key, 'public'));
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

        return new self($key, true, self::detectCurve($key, 'private'));
    }

    /**
     * Build a public key from raw point coordinates (as carried in a COSE key or
     * JWK), each left-padded to the curve's fixed coordinate length.
     *
     * @throws KeyLoadException|WeakKeyException
     */
    public static function fromCoordinates(string $x, string $y, string $curve = self::DEFAULT_CURVE): self
    {
        $parameters = self::CURVES[$curve] ?? throw WeakKeyException::unsupportedCurve($curve);

        if (strlen($x) !== $parameters['bytes'] || strlen($y) !== $parameters['bytes']) {
            throw KeyLoadException::unreadable('public');
        }

        return self::public(Asn1::ecPublicKeyPem("\x04".$x.$y, $parameters['oid']));
    }

    /**
     * Generate a fresh EC private key on the given curve.
     *
     * @throws KeyLoadException|WeakKeyException
     */
    public static function generate(string $curve = self::DEFAULT_CURVE): self
    {
        $parameters = self::CURVES[$curve] ?? throw WeakKeyException::unsupportedCurve($curve);

        $key = OpenSsl::generateKey([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => $parameters['openssl'],
        ]);

        return new self($key, true, $curve);
    }

    public function algorithm(): Algorithm
    {
        return self::CURVES[$this->curve]['algorithm'];
    }

    /**
     * The fixed byte length of each ECDSA coordinate on this key's curve.
     */
    public function coordinateBytes(): int
    {
        return self::CURVES[$this->curve]['bytes'];
    }

    public function verifier(): Verifier
    {
        return new Es($this);
    }

    /**
     * @throws KeyLoadException
     */
    private static function detectCurve(OpenSSLAsymmetricKey $key, string $kind): string
    {
        $details = openssl_pkey_get_details($key);

        if ($details === false || ($details['type'] ?? null) !== OPENSSL_KEYTYPE_EC) {
            throw KeyLoadException::wrongType($kind, 'EC');
        }

        $curveName = $details['ec']['curve_name'] ?? null;

        if (! is_string($curveName) || ! isset(self::OPENSSL_CURVES[$curveName])) {
            throw KeyLoadException::unsupportedCurve(is_string($curveName) ? $curveName : 'unknown');
        }

        return self::OPENSSL_CURVES[$curveName];
    }
}
