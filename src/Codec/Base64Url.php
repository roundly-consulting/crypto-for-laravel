<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Codec;

/**
 * Strict base64url (RFC 7515 §2 / RFC 4648 §5) codec.
 *
 * Encoding produces the unpadded URL-safe alphabet. Decoding is deliberately
 * strict: it rejects any input carrying standard-base64 characters (`+`, `/`,
 * `=`) or bytes outside the base64url alphabet, so a tampered segment never
 * silently decodes into different bytes.
 */
final class Base64Url
{
    public static function encode(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    /**
     * @throws InvalidEncodingException when the input is not valid, unpadded base64url.
     */
    public static function decode(string $text): string
    {
        // Reject anything outside the base64url alphabet up front — including the
        // standard-base64 `+`, `/` and any stray `=` padding.
        if ($text === '' || preg_match('/[^A-Za-z0-9_-]/', $text) === 1) {
            throw InvalidEncodingException::base64Url();
        }

        $remainder = strlen($text) % 4;

        if ($remainder === 1) {
            // A single leftover char can never be a whole base64 group.
            throw InvalidEncodingException::base64Url();
        }

        $padded = $remainder === 0
            ? $text
            : $text.str_repeat('=', 4 - $remainder);

        $decoded = base64_decode(strtr($padded, '-_', '+/'), true);

        if ($decoded === false) {
            throw InvalidEncodingException::base64Url();
        }

        return $decoded;
    }
}
