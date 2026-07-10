<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Codec;

/**
 * RFC 4648 base32 codec over the alphabet A–Z2–7, without padding on encode.
 *
 * The decoder is case-insensitive but otherwise strict and canonical: it accepts
 * `=` only as a proper tail-padding run (never in the interior), rejects any
 * character outside the alphabet (no whitespace stripping), rejects a dangling
 * character that encodes no byte, and rejects a non-zero sub-byte remainder. That
 * makes decoding injective — no two distinct in-alphabet strings map to the same
 * bytes — while still decoding the unpadded secrets authenticator apps produce.
 */
final class Base32
{
    public const string ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    /** Valid `=` padding lengths for a base32 group (2/4/5/7 data chars). */
    private const array VALID_PADDING = [1, 3, 4, 6];

    public static function encode(string $bytes): string
    {
        if ($bytes === '') {
            return '';
        }

        $binary = '';

        foreach (str_split($bytes) as $byte) {
            $binary .= str_pad(decbin(ord($byte)), 8, '0', STR_PAD_LEFT);
        }

        $output = '';

        foreach (str_split($binary, 5) as $chunk) {
            $chunk = str_pad($chunk, 5, '0', STR_PAD_RIGHT);
            $output .= self::ALPHABET[(int) bindec($chunk)];
        }

        return $output;
    }

    /**
     * @throws InvalidEncodingException when the value is not canonical base32:
     *                                  a bad character, interior `=`, an invalid
     *                                  padding run, a dangling character, or a
     *                                  non-zero sub-byte remainder.
     */
    public static function decode(string $base32): string
    {
        $normalized = strtoupper($base32);

        // '=' is padding, valid only as a run at the very end. Split it off; any
        // '=' left in the body is interior padding and is rejected.
        $body = rtrim($normalized, '=');
        $padding = strlen($normalized) - strlen($body);

        if (str_contains($body, '=')) {
            throw InvalidEncodingException::base32('=');
        }

        if ($padding !== 0
            && (strlen($normalized) % 8 !== 0 || ! in_array($padding, self::VALID_PADDING, true))) {
            throw InvalidEncodingException::base32('=');
        }

        if ($body === '') {
            return '';
        }

        $binary = '';

        foreach (str_split($body) as $character) {
            $position = strpos(self::ALPHABET, $character);

            if ($position === false) {
                throw InvalidEncodingException::base32($character);
            }

            $binary .= str_pad(decbin($position), 5, '0', STR_PAD_LEFT);
        }

        $remainder = strlen($binary) % 8;

        // Five or more leftover bits is a whole dangling character that encodes no
        // byte — an impossible canonical length (2/4/5/7 chars per group).
        if ($remainder >= 5) {
            throw InvalidEncodingException::base32($body[strlen($body) - 1]);
        }

        // The sub-byte remainder must be all zero; a non-zero tail is
        // non-canonical and would break injectivity.
        if ($remainder !== 0 && substr($binary, -$remainder) !== str_repeat('0', $remainder)) {
            throw InvalidEncodingException::nonCanonicalBase32();
        }

        $bytes = '';

        foreach (str_split(substr($binary, 0, strlen($binary) - $remainder), 8) as $chunk) {
            $bytes .= chr((int) bindec($chunk));
        }

        return $bytes;
    }
}
