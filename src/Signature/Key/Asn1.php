<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Signature\Key;

/**
 * Minimal ASN.1/DER assembly for SubjectPublicKeyInfo (SPKI) PEM material.
 *
 * Builds the PEM ext-openssl needs to verify signatures from raw EC (P-256)
 * point coordinates or raw RSA modulus/exponent bytes — the form COSE keys and
 * JWKs carry them in.
 *
 * @internal
 */
final class Asn1
{
    // Pre-encoded DER for the algorithm-identifier OIDs (fixed byte templates).
    private const string OID_EC_PUBLIC_KEY = "\x06\x07\x2A\x86\x48\xCE\x3D\x02\x01";

    private const string OID_RSA_ENCRYPTION = "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01";

    private const string DER_NULL = "\x05\x00";

    /**
     * Assemble an EC public key PEM from an uncompressed point and the DER-encoded
     * named-curve OID (P-256 / P-384 / P-521).
     */
    public static function ecPublicKeyPem(string $uncompressedPoint, string $curveOid): string
    {
        $algorithm = self::sequence(self::OID_EC_PUBLIC_KEY.$curveOid);
        $spki = self::sequence($algorithm.self::bitString($uncompressedPoint));

        return self::pem($spki);
    }

    /**
     * Assemble an RSA public key PEM from raw modulus and exponent bytes.
     */
    public static function rsaPublicKeyPem(string $modulus, string $exponent): string
    {
        $rsaKey = self::sequence(self::integer($modulus).self::integer($exponent));
        $algorithm = self::sequence(self::OID_RSA_ENCRYPTION.self::DER_NULL);
        $spki = self::sequence($algorithm.self::bitString($rsaKey));

        return self::pem($spki);
    }

    private static function integer(string $bytes): string
    {
        $bytes = ltrim($bytes, "\x00");

        if ($bytes === '') {
            $bytes = "\x00";
        }

        if ((ord($bytes[0]) & 0x80) !== 0) {
            $bytes = "\x00".$bytes;
        }

        return "\x02".self::length($bytes).$bytes;
    }

    private static function sequence(string $content): string
    {
        return "\x30".self::length($content).$content;
    }

    private static function bitString(string $content): string
    {
        // Leading 0x00 = number of unused bits in the final byte (always zero here).
        $content = "\x00".$content;

        return "\x03".self::length($content).$content;
    }

    private static function length(string $content): string
    {
        $length = strlen($content);

        if ($length < 0x80) {
            return chr($length);
        }

        $bytes = '';

        while ($length > 0) {
            $bytes = chr($length & 0xFF).$bytes;
            $length >>= 8;
        }

        return chr(0x80 | strlen($bytes)).$bytes;
    }

    private static function pem(string $der): string
    {
        $base64 = chunk_split(base64_encode($der), 64, "\n");

        return "-----BEGIN PUBLIC KEY-----\n{$base64}-----END PUBLIC KEY-----\n";
    }
}
