<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Hash;

/**
 * The digest algorithms supported for HMAC and plain hashing.
 *
 * The backing value is the exact name understood by PHP's hash() / hash_hmac().
 *
 * SHA-1 is retained only for interoperating with legacy systems: it is
 * collision-broken and must not be chosen for new digest or HMAC work — prefer
 * SHA-256 or stronger. (OTP is separate: RFC 6238 mandates SHA-1 there and
 * authenticator apps default to it, so {@see \RoundlyConsulting\Crypto\Otp\OtpAlgorithm}
 * keeps it first-class.) Check {@see isLegacy()} to flag an accidental choice.
 */
enum HashAlgorithm: string
{
    case Sha1 = 'sha1';
    case Sha256 = 'sha256';
    case Sha384 = 'sha384';
    case Sha512 = 'sha512';

    /**
     * Whether this algorithm is retained for legacy interop only and should not
     * be used for new digest/HMAC work.
     */
    public function isLegacy(): bool
    {
        return $this === self::Sha1;
    }
}
