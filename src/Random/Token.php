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
     * A URL-safe token of exactly $length base64url characters, backed by a
     * CSPRNG.
     *
     * @throws InvalidLengthException when below {@see self::MINIMUM_LENGTH}
     */
    public static function urlSafe(int $length = 40): string
    {
        if ($length < self::MINIMUM_LENGTH) {
            throw InvalidLengthException::tooShort($length, self::MINIMUM_LENGTH);
        }

        // base64url yields ~4 chars per 3 bytes; over-generate then trim to the
        // exact requested character count.
        $bytes = Bytes::generate((int) ceil($length * 3 / 4) + 1);

        return substr(Base64Url::encode($bytes), 0, $length);
    }

    /**
     * A token of $length characters drawn uniformly from the given alphabet.
     *
     * @throws InvalidLengthException when the alphabet is empty or $length < 1
     */
    public static function fromAlphabet(string $alphabet, int $length): string
    {
        if ($alphabet === '') {
            throw InvalidLengthException::emptyAlphabet();
        }

        if ($length < 1) {
            throw InvalidLengthException::tooShort($length, 1);
        }

        $max = strlen($alphabet) - 1;
        $token = '';

        for ($i = 0; $i < $length; $i++) {
            $token .= $alphabet[random_int(0, $max)];
        }

        return $token;
    }
}
