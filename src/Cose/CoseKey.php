<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Cose;

use RoundlyConsulting\Crypto\Signature\Key\EcKey;
use RoundlyConsulting\Crypto\Signature\Key\OkpKey;
use RoundlyConsulting\Crypto\Signature\Key\PublicKey;
use RoundlyConsulting\Crypto\Signature\Key\RsaKey;

/**
 * Turns COSE_Key bytes into a verifiable {@see PublicKey}.
 *
 * COSE_Key labels (RFC 9052 / RFC 9053): 1 = kty, 3 = alg, -1 = crv (EC/OKP) or
 * n (RSA), -2 = x or e (RSA), -3 = y. kty: 1 = OKP, 2 = EC2, 3 = RSA.
 * crv: 1 = P-256, 2 = P-384, 3 = P-521, 6 = Ed25519.
 *
 * It reads the BYTES, not an already-decoded array: a PHP string cannot say
 * whether CBOR carried it as a byte string or a text string, and a key material
 * field (x, y, n, e) must be a byte string — a strict COSE implementation
 * rejects a text-typed coordinate, so this one does too.
 */
final class CoseKey
{
    /** CBOR major types a COSE_Key field may carry. */
    private const int UNSIGNED = 0;

    private const int NEGATIVE = 1;

    private const int BYTE_STRING = 2;

    /**
     * COSE EC2 curve label → [our curve label, the ES* algorithm it requires].
     *
     * @var array<int, array{string, CoseAlgorithm}>
     */
    private const array EC2_CURVES = [
        1 => ['P-256', CoseAlgorithm::ES256],
        2 => ['P-384', CoseAlgorithm::ES384],
        3 => ['P-521', CoseAlgorithm::ES512],
    ];

    /**
     * @throws MalformedCborException|UnsupportedAlgorithmException
     */
    public static function fromCbor(string $bytes): PublicKey
    {
        $cose = (new CborDecoder)->decodeMapWithTypes($bytes);
        $kty = self::int($cose, 1, 'kty');
        $algorithm = self::algorithm($cose);

        return match ($kty) {
            2 => self::ec2($cose, $algorithm),
            3 => self::rsa($cose, $algorithm),
            1 => self::okp($cose, $algorithm),
            default => throw UnsupportedAlgorithmException::keyType($kty),
        };
    }

    /**
     * @param  array<int|string, array{int, mixed}>  $cose
     */
    private static function ec2(array $cose, CoseAlgorithm $algorithm): EcKey
    {
        $curve = self::int($cose, -1, 'crv');

        [$curveLabel, $expectedAlgorithm] = self::EC2_CURVES[$curve]
            ?? throw UnsupportedAlgorithmException::curve($curve);

        if ($algorithm !== $expectedAlgorithm) {
            throw UnsupportedAlgorithmException::forId($algorithm->value);
        }

        return EcKey::fromCoordinates(
            self::bytes($cose, -2, 'x'),
            self::bytes($cose, -3, 'y'),
            $curveLabel,
        );
    }

    /**
     * @param  array<int|string, array{int, mixed}>  $cose
     */
    private static function rsa(array $cose, CoseAlgorithm $algorithm): RsaKey
    {
        if ($algorithm !== CoseAlgorithm::RS256) {
            throw UnsupportedAlgorithmException::forId($algorithm->value);
        }

        return RsaKey::fromModulusExponent(
            self::bytes($cose, -1, 'n'),
            self::bytes($cose, -2, 'e'),
        );
    }

    /**
     * @param  array<int|string, array{int, mixed}>  $cose
     */
    private static function okp(array $cose, CoseAlgorithm $algorithm): OkpKey
    {
        if ($algorithm !== CoseAlgorithm::EdDSA) {
            throw UnsupportedAlgorithmException::forId($algorithm->value);
        }

        $curve = self::int($cose, -1, 'crv');

        if ($curve !== 6) {
            throw UnsupportedAlgorithmException::curve($curve);
        }

        return OkpKey::ed25519(self::bytes($cose, -2, 'x'));
    }

    /**
     * @param  array<int|string, array{int, mixed}>  $cose
     */
    private static function algorithm(array $cose): CoseAlgorithm
    {
        $alg = self::int($cose, 3, 'alg');

        return CoseAlgorithm::tryFrom($alg) ?? throw UnsupportedAlgorithmException::forId($alg);
    }

    /**
     * @param  array<int|string, array{int, mixed}>  $cose
     */
    private static function int(array $cose, int $label, string $name): int
    {
        [$type, $value] = $cose[$label] ?? [null, null];

        if (($type !== self::UNSIGNED && $type !== self::NEGATIVE) || ! is_int($value)) {
            throw MalformedCborException::make("missing or non-integer {$name}");
        }

        return $value;
    }

    /**
     * @param  array<int|string, array{int, mixed}>  $cose
     */
    private static function bytes(array $cose, int $label, string $name): string
    {
        [$type, $value] = $cose[$label] ?? [null, null];

        if ($type !== self::BYTE_STRING || ! is_string($value) || $value === '') {
            throw MalformedCborException::make("missing or non-binary {$name}");
        }

        return $value;
    }
}
