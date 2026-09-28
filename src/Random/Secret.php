<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Random;

use RoundlyConsulting\Crypto\Codec\Base32;

/**
 * A TOTP-style shared secret: CSPRNG bytes rendered as base32 over the RFC 4648
 * alphabet, always in a form this package's own strict {@see Base32::decode()},
 * {@see \RoundlyConsulting\Crypto\Otp\Totp} and {@see \RoundlyConsulting\Crypto\Otp\Hotp} accept.
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
     * Base32 lengths (mod 8) that no byte string encodes to: the last character
     * would carry five or more bits of no byte, which the strict decoder rejects.
     *
     * @var list<int>
     */
    private const array DANGLING_REMAINDERS = [1, 3, 6];

    /**
     * A secret of exactly `$chars` characters — or `$chars + 1` when `$chars` is
     * 1, 3 or 6 (mod 8), a length no canonical base32 string has. Rounding UP
     * keeps at least the requested entropy; rounding down would quietly weaken it.
     *
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

        // MAXIMUM_CHARS is ≡ 0 (mod 8), so the round-up never crosses it.
        if (in_array($chars % 8, self::DANGLING_REMAINDERS, true)) {
            $chars++;
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
