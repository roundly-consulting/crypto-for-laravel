<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Random;

use RoundlyConsulting\Crypto\Codec\Base64Url;

/**
 * High-entropy opaque tokens (bearer tokens, refresh tokens, one-time codes).
 */
final class Token
{
    /**
     * The shortest token this class will mint. Below this a token is
     * brute-forceable; a caller asking for less fails loudly, not silently.
     */
    public const int MINIMUM_LENGTH = 32;

    /**
     * A sane ceiling on token length. Far above any real bearer/refresh token, it
     * stops a caller wiring the length to untrusted input from self-inflicting a
     * DoS.
     */
    public const int MAXIMUM_LENGTH = 4096;

    /**
     * A URL-safe token of exactly $length base64url characters, backed by a
     * CSPRNG.
     *
     * @throws InvalidLengthException when below {@see self::MINIMUM_LENGTH} or
     *                                above {@see self::MAXIMUM_LENGTH}
     */
    public static function urlSafe(int $length = 40): string
    {
        if ($length < self::MINIMUM_LENGTH) {
            throw InvalidLengthException::tooShort($length, self::MINIMUM_LENGTH);
        }

        if ($length > self::MAXIMUM_LENGTH) {
            throw InvalidLengthException::tooLong($length, self::MAXIMUM_LENGTH);
        }

        // base64url yields ~4 chars per 3 bytes; over-generate then trim to the
        // exact requested character count.
        $bytes = Bytes::generate((int) ceil($length * 3 / 4) + 1);

        return substr(Base64Url::encode($bytes), 0, $length);
    }

    /**
     * The digit alphabet for {@see self::numeric()}.
     */
    public const string DIGITS = '0123456789';

    /**
     * The case-sensitive alphanumeric alphabet for {@see self::alphanumeric()}.
     */
    public const string ALPHANUMERIC = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

    /**
     * A digits-only token of exactly $length characters (recovery codes, numeric
     * OTPs), drawn uniformly with a CSPRNG.
     *
     * @throws InvalidLengthException when $length < 1
     */
    public static function numeric(int $length): string
    {
        return self::fromAlphabet(self::DIGITS, $length);
    }

    /**
     * An alphanumeric token of exactly $length characters, drawn uniformly with a
     * CSPRNG.
     *
     * @throws InvalidLengthException when $length < 1
     */
    public static function alphanumeric(int $length): string
    {
        return self::fromAlphabet(self::ALPHANUMERIC, $length);
    }

    /**
     * A token of $length characters drawn uniformly from the given alphabet.
     *
     * The alphabet is UTF-8 TEXT and is drawn from character by character, so a
     * multibyte alphabet (`'äöü'`, emoji) yields valid UTF-8 of exactly $length
     * characters — indexing bytes would split a character in half.
     *
     * @throws InvalidLengthException when the alphabet is empty or not UTF-8, or $length < 1
     */
    public static function fromAlphabet(string $alphabet, int $length): string
    {
        if ($alphabet === '') {
            throw InvalidLengthException::emptyAlphabet();
        }

        if (! mb_check_encoding($alphabet, 'UTF-8')) {
            throw InvalidLengthException::alphabetNotUtf8();
        }

        if ($length < 1) {
            throw InvalidLengthException::tooShort($length, 1);
        }

        if ($length > self::MAXIMUM_LENGTH) {
            throw InvalidLengthException::tooLong($length, self::MAXIMUM_LENGTH);
        }

        $characters = mb_str_split($alphabet, 1, 'UTF-8');
        $max = count($characters) - 1;
        $token = '';

        for ($i = 0; $i < $length; $i++) {
            $token .= $characters[random_int(0, $max)];
        }

        return $token;
    }
}
