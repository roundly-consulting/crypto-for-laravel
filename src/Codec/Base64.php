<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Codec;

use SensitiveParameter;

/**
 * Strict standard (padded) base64 (RFC 4648 §4) codec.
 *
 * Unlike {@see Base64Url}, this uses the `+`/`/` alphabet with `=` padding, for
 * interop with webhook and provider schemes that carry standard base64. Decoding
 * is strict: it rejects any byte outside the alphabet, wrong or missing padding,
 * and stray whitespace, so a tampered value never silently decodes.
 *
 * Both directions take `#[SensitiveParameter]` input: OTP secrets, token bytes
 * and keys pass through the codecs, as they do through PHP's own sodium codecs.
 */
final class Base64
{
    public static function encode(#[SensitiveParameter] string $bytes): string
    {
        return base64_encode($bytes);
    }

    /**
     * @throws InvalidEncodingException when the input is not valid, padded base64.
     */
    public static function decode(#[SensitiveParameter] string $text): string
    {
        // Enforce canonical form up front: only the standard alphabet, a length
        // that is a multiple of four, and padding only at the tail.
        if ($text === '' || strlen($text) % 4 !== 0 || preg_match('#^[A-Za-z0-9+/]+={0,2}$#', $text) !== 1) {
            throw InvalidEncodingException::base64();
        }

        // Strict mode also rejects non-canonical encodings the regex allows.
        $decoded = base64_decode($text, true);

        if ($decoded === false || base64_encode($decoded) !== $text) {
            throw InvalidEncodingException::base64();
        }

        return $decoded;
    }
}
