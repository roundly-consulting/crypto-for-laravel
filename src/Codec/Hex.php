<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Codec;

/**
 * Lower-case hexadecimal codec with strict decoding.
 */
final class Hex
{
    public static function encode(string $bytes): string
    {
        return bin2hex($bytes);
    }

    /**
     * @throws InvalidEncodingException when the input is not valid hexadecimal.
     */
    public static function decode(string $hex): string
    {
        // An odd length or any non-hex character is never a valid byte string.
        if (strlen($hex) % 2 !== 0 || ($hex !== '' && ctype_xdigit($hex) === false)) {
            throw InvalidEncodingException::hex();
        }

        $decoded = @hex2bin($hex);

        if ($decoded === false) {
            throw InvalidEncodingException::hex();
        }

        return $decoded;
    }
}
