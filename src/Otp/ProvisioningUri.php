<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Otp;

use RoundlyConsulting\Crypto\Codec\Base32;
use RoundlyConsulting\Crypto\Codec\InvalidEncodingException;
use SensitiveParameter;

/**
 * Builds the `otpauth://totp/...` provisioning URI authenticator apps import
 * (the Key URI Format). The issuer is always an explicit argument — this class
 * reads no configuration.
 */
final class ProvisioningUri
{
    /**
     * The secret is what the authenticator app enrols, so it must be one this
     * package's {@see Totp} can decode: canonical base32 holding at least one
     * byte. It is written uppercase and unpadded, the form authenticator apps
     * expect.
     *
     * @throws InvalidOtpParameterException when digits or period are out of range, or the secret is empty
     * @throws InvalidEncodingException when the secret is not canonical base32
     */
    public static function totp(
        #[SensitiveParameter] string $secret,
        string $label,
        string $issuer,
        OtpAlgorithm $algorithm = OtpAlgorithm::Sha1,
        int $digits = 6,
        int $period = 30,
    ): string {
        if ($digits < 6 || $digits > 10) {
            throw InvalidOtpParameterException::digits($digits);
        }

        if ($period < 1) {
            throw InvalidOtpParameterException::period($period);
        }

        $key = Base32::decode($secret);

        if ($key === '') {
            throw InvalidOtpParameterException::emptySecret();
        }

        $query = http_build_query([
            'secret' => Base32::encode($key),
            'issuer' => $issuer,
            'algorithm' => strtoupper($algorithm->value),
            'digits' => $digits,
            'period' => $period,
        ], '', '&', PHP_QUERY_RFC3986);

        return sprintf(
            'otpauth://totp/%s:%s?%s',
            rawurlencode($issuer),
            rawurlencode($label),
            $query,
        );
    }
}
