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
     * @throws InvalidLengthException when fewer than one character is requested.
     */
    public static function base32(int $chars = 32): string
    {
        if ($chars < 1) {
            throw InvalidLengthException::tooShort($chars, 1);
        }

        // Each base32 char encodes 5 bits; over-generate raw bytes then trim so
        // the output is exactly $chars characters over the RFC 4648 alphabet.
        $rawBytes = (int) ceil($chars * 5 / 8) + 1;

        return substr(Base32::encode(Bytes::generate($rawBytes)), 0, $chars);
    }
}
