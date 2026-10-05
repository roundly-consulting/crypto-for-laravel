<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Otp;

use RoundlyConsulting\Crypto\Codec\Base32;
use RoundlyConsulting\Crypto\Codec\InvalidEncodingException;
use SensitiveParameter;

/**
 * RFC 4226 HMAC-based one-time passwords (HOTP).
 *
 * The secret is the base32 text an authenticator app displays; it is decoded to
 * key bytes internally. It must decode to at least {@see self::MIN_SECRET_BYTES}
 * bytes that are not all zero: HMAC zero-pads a short key, so an empty or
 * all-zero key yields codes anyone can compute.
 */
final readonly class Hotp
{
    /**
     * The shortest secret accepted, in decoded bytes (80 bits). RFC 4226 §4
     * requires 128 bits and recommends 160 — {@see \RoundlyConsulting\Crypto\Random\Secret::base32()}
     * generates 160 by default — but 80-bit (16-character) secrets are what
     * authenticator apps have been issued for years, so the hard floor stays
     * where existing enrolments still verify.
     */
    public const int MIN_SECRET_BYTES = 10;

    public function __construct(
        private OtpAlgorithm $algorithm = OtpAlgorithm::Sha1,
        private int $digits = 6,
    ) {
        if ($digits < 6 || $digits > 10) {
            throw InvalidOtpParameterException::digits($digits);
        }
    }

    /**
     * The RFC 4226 HOTP value for a base32 secret and counter.
     *
     * @throws InvalidEncodingException when the secret is not canonical base32
     * @throws InvalidOtpParameterException when the secret is empty, shorter than
     *                                      {@see self::MIN_SECRET_BYTES}, or all zero bytes
     */
    public function at(#[SensitiveParameter] string $secret, int $counter): string
    {
        $key = Base32::decode($secret);

        if ($key === '') {
            throw InvalidOtpParameterException::emptySecret();
        }

        if (strlen($key) < self::MIN_SECRET_BYTES) {
            throw InvalidOtpParameterException::shortSecret(self::MIN_SECRET_BYTES);
        }

        if (trim($key, "\0") === '') {
            throw InvalidOtpParameterException::zeroSecret();
        }

        $hash = hash_hmac($this->algorithm->value, pack('J', $counter), $key, true);

        $offset = ord($hash[strlen($hash) - 1]) & 0x0F;

        $binary = ((ord($hash[$offset]) & 0x7F) << 24)
            | ((ord($hash[$offset + 1]) & 0xFF) << 16)
            | ((ord($hash[$offset + 2]) & 0xFF) << 8)
            | (ord($hash[$offset + 3]) & 0xFF);

        // The truncated value is 31 bits (max 2,147,483,647 — ten digits), so a
        // modulus of 10^10 or more is a no-op. Skipping it keeps the arithmetic
        // inside a 32-bit signed int, since 10^10 overflows one. This makes the
        // full 6–10 digit range correct on 32-bit PHP as well as 64-bit.
        $otp = $this->digits >= 10 ? $binary : $binary % (10 ** $this->digits);

        return str_pad((string) $otp, $this->digits, '0', STR_PAD_LEFT);
    }

    public function digits(): int
    {
        return $this->digits;
    }

    public function algorithm(): OtpAlgorithm
    {
        return $this->algorithm;
    }
}
