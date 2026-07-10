<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Signature\Ec;

use RoundlyConsulting\Crypto\Signature\InvalidSignatureException;

/**
 * ECDSA signature-encoding codec.
 *
 * Converts between the fixed raw `r‖s` concatenation that JOSE (ES256) and
 * WebAuthn deliver and the ASN.1 DER `SEQUENCE { INTEGER r, INTEGER s }` that
 * ext-openssl produces and consumes. This was independently reimplemented three
 * times across the fleet; it lives here once.
 */
final class Der
{
    /**
     * Convert a raw `r‖s` signature (each integer $coordBytes long) to DER.
     *
     * @throws InvalidSignatureException when the raw signature is the wrong length
     */
    public static function fromRaw(string $rawRS, int $coordBytes = 32): string
    {
        if (strlen($rawRS) !== $coordBytes * 2) {
            throw InvalidSignatureException::make();
        }

        $r = self::integer(substr($rawRS, 0, $coordBytes));
        $s = self::integer(substr($rawRS, $coordBytes));

        return self::sequence($r.$s);
    }

    /**
     * Convert a DER `SEQUENCE { INTEGER r, INTEGER s }` to raw `r‖s`, each
     * integer left-padded to $coordBytes.
     *
     * @throws InvalidSignatureException when the DER is not a valid ECDSA signature
     */
    public static function toRaw(string $der, int $coordBytes = 32): string
    {
        if (! self::isValid($der)) {
            throw InvalidSignatureException::make();
        }

        $offset = 1;
        self::readLength($der, $offset);

        $r = self::readInteger($der, $offset);
        $s = self::readInteger($der, $offset);

        if (strlen($r) > $coordBytes || strlen($s) > $coordBytes) {
            throw InvalidSignatureException::make();
        }

        return self::pad($r, $coordBytes).self::pad($s, $coordBytes);
    }

    /**
     * Whether the bytes are a well-formed, minimally-encoded ECDSA DER
     * signature — `SEQUENCE { INTEGER r, INTEGER s }` with nothing trailing.
     */
    public static function isValid(string $der): bool
    {
        $length = strlen($der);

        if ($length < 8 || $der[0] !== "\x30") {
            return false;
        }

        $offset = 1;
        $seqLen = self::readDerLength($der, $offset);

        if ($seqLen === null || $offset + $seqLen !== $length) {
            return false;
        }

        foreach ([0, 1] as $ignored) {
            if ($offset >= $length || $der[$offset] !== "\x02") {
                return false;
            }

            $offset++;
            $intLen = self::readDerLength($der, $offset);

            if ($intLen === null || $intLen < 1 || $offset + $intLen > $length) {
                return false;
            }

            if (! self::isMinimalInteger(substr($der, $offset, $intLen))) {
                return false;
            }

            $offset += $intLen;
        }

        return $offset === $length;
    }

    private static function readInteger(string $der, int &$offset): string
    {
        // Structure already validated by isValid(); advance past the INTEGER tag.
        $offset++;
        $length = self::readLength($der, $offset);
        $value = substr($der, $offset, $length);
        $offset += $length;

        return ltrim($value, "\x00");
    }

    private static function pad(string $value, int $coordBytes): string
    {
        return str_pad($value, $coordBytes, "\x00", STR_PAD_LEFT);
    }

    private static function isMinimalInteger(string $content): bool
    {
        // A leading 0x00 is only allowed to keep a high-bit-set value positive.
        if ($content[0] === "\x00") {
            return strlen($content) > 1 && (ord($content[1]) & 0x80) !== 0;
        }

        // A negative integer (high bit set) is never valid for r/s.
        return (ord($content[0]) & 0x80) === 0;
    }

    private static function readLength(string $der, int &$offset): int
    {
        $length = self::readDerLength($der, $offset);

        // Only ever called after isValid(), so a null here is unreachable.
        return $length ?? 0;
    }

    private static function readDerLength(string $der, int &$offset): ?int
    {
        if ($offset >= strlen($der)) {
            return null;
        }

        $first = ord($der[$offset++]);

        if ($first < 0x80) {
            return $first;
        }

        $count = $first & 0x7F;

        if ($count === 0 || $count > 4 || $offset + $count > strlen($der)) {
            return null;
        }

        // DER requires the minimal length encoding: no leading zero octet in the
        // long form. Rejecting it closes the BER length-malleability Wycheproof
        // flags (a leading-0x00 length is non-canonical).
        if ($der[$offset] === "\x00") {
            return null;
        }

        $value = 0;

        for ($i = 0; $i < $count; $i++) {
            $value = ($value << 8) | ord($der[$offset++]);
        }

        // A value that fits in short form must use it; the long form here is
        // non-minimal (again BER, not DER) and is rejected.
        if ($value < 0x80) {
            return null;
        }

        return $value;
    }

    private static function integer(string $bytes): string
    {
        $bytes = ltrim($bytes, "\x00");

        if ($bytes === '') {
            $bytes = "\x00";
        }

        // Prepend a zero byte when the high bit is set to keep the value positive.
        if ((ord($bytes[0]) & 0x80) !== 0) {
            $bytes = "\x00".$bytes;
        }

        return "\x02".self::lengthBytes($bytes).$bytes;
    }

    private static function sequence(string $content): string
    {
        return "\x30".self::lengthBytes($content).$content;
    }

    private static function lengthBytes(string $content): string
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
}
