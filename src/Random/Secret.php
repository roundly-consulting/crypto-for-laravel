<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Random;

use RoundlyConsulting\Crypto\Codec\Base32;

/**
 * A TOTP-style shared secret: CSPRNG bytes rendered as base32 over the RFC 4648
 * alphabet, at an exact character length any authenticator app accepts.
 */
final class Secret
{
    /**
     * A sane ceiling on secret length; far above any authenticator secret, it
     * stops a caller wiring the length to untrusted input from self-inflicting a
     * DoS.
     */
    public const int MAXIMUM_CHARS = 4096;

    /**
     * @throws InvalidLengthException when fewer than one, or more than
     *                                {@see self::MAXIMUM_CHARS}, characters are requested.
     */
    public static function base32(int $chars = 32): string
    {
        if ($chars < 1) {
            throw InvalidLengthException::tooShort($chars, 1);
        }

        if ($chars > self::MAXIMUM_CHARS) {
            throw InvalidLengthException::tooLong($chars, self::MAXIMUM_CHARS);
        }

        // Each base32 char encodes 5 bits; over-generate raw bytes then trim so
        // the output is exactly $chars characters over the RFC 4648 alphabet.
        $rawBytes = (int) ceil($chars * 5 / 8) + 1;
        $secret = substr(Base32::encode(Bytes::generate($rawBytes)), 0, $chars);

        return self::canonicalize($secret, $chars);
    }

    /**
     * Trimming to an arbitrary character count can leave a non-zero sub-byte
     * remainder in the final character, which the strict decoder rejects. Zero
     * those remainder bits so the secret is canonical and round-trips.
     */
    private static function canonicalize(string $secret, int $chars): string
    {
        $remainder = ($chars * 5) % 8;

        if ($remainder === 0) {
            return $secret;
        }

        $last = strpos(Base32::ALPHABET, $secret[$chars - 1]);
        $secret[$chars - 1] = Base32::ALPHABET[(int) $last & ~((1 << $remainder) - 1)];

        return $secret;
    }
}
