<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Otp;

use RoundlyConsulting\Crypto\Codec\Base32;
use SensitiveParameter;

/**
 * RFC 4226 HMAC-based one-time passwords (HOTP).
 *
 * The secret is the base32 text an authenticator app displays; it is decoded to
 * key bytes internally.
 */
final readonly class Hotp
{
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
     */
    public function at(#[SensitiveParameter] string $secret, int $counter): string
    {
        $key = Base32::decode($secret);
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
