<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Otp;

/**
 * The HMAC hash algorithms permitted for HOTP/TOTP (RFC 4226 / RFC 6238).
 *
 * The backing value is both the hash_hmac() name and the `algorithm` parameter
 * of an otpauth:// URI (upper-cased).
 */
enum OtpAlgorithm: string
{
    case Sha1 = 'sha1';
    case Sha256 = 'sha256';
    case Sha512 = 'sha512';
}
