<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Random;

/**
 * `Crypto::random()` — every CSPRNG helper in one place: raw bytes, URL-safe,
 * numeric, alphanumeric and custom-alphabet tokens, and base32 secrets.
 *
 * Pure delegation to {@see Bytes}, {@see Token} and {@see Secret}: same length
 * bounds, same `InvalidLengthException`s, same uniform draws.
 */
final readonly class Csprng
{
    /**
     * @throws InvalidLengthException below 1 or above {@see Bytes::MAXIMUM_LENGTH} bytes
     */
    public function bytes(int $length): string
    {
        return Bytes::generate($length);
    }

    /**
     * A URL-safe (base64url) token of exactly $length characters.
     *
     * @throws InvalidLengthException below {@see Token::MINIMUM_LENGTH} or above {@see Token::MAXIMUM_LENGTH}
     */
    public function token(int $length = 40): string
    {
        return Token::urlSafe($length);
    }

    /**
     * Digits only — recovery codes, numeric one-time codes.
     *
     * @throws InvalidLengthException when $length < 1
     */
    public function numeric(int $length): string
    {
        return Token::numeric($length);
    }

    /**
     * `0-9A-Za-z`, drawn uniformly.
     *
     * @throws InvalidLengthException when $length < 1
     */
    public function alphanumeric(int $length): string
    {
        return Token::alphanumeric($length);
    }

    /**
     * @throws InvalidLengthException when the alphabet is empty or $length < 1
     */
    public function fromAlphabet(string $alphabet, int $length): string
    {
        return Token::fromAlphabet($alphabet, $length);
    }

    /**
     * A TOTP-ready base32 secret of $chars characters (one more when $chars is
     * 1, 3 or 6 mod 8 — see {@see Secret::base32()}).
     *
     * @throws InvalidLengthException below 1 or above {@see Secret::MAXIMUM_CHARS} characters
     */
    public function secret(int $chars = 32): string
    {
        return Secret::base32($chars);
    }
}
