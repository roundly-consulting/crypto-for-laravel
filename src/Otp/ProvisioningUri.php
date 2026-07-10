<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Otp;

use SensitiveParameter;

/**
 * Builds the `otpauth://totp/...` provisioning URI authenticator apps import
 * (the Key URI Format). The issuer is always an explicit argument — this class
 * reads no configuration.
 */
final class ProvisioningUri
{
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

        $query = http_build_query([
            'secret' => $secret,
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
