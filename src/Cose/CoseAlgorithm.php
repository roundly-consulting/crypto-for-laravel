<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Cose;

use RoundlyConsulting\Crypto\Signature\Algorithm;

/**
 * COSE algorithm identifiers (IANA COSE registry) supported for WebAuthn
 * verification.
 */
enum CoseAlgorithm: int
{
    case ES256 = -7;
    case EdDSA = -8;
    case ES384 = -35;
    case ES512 = -36;
    case RS256 = -257;

    /**
     * The equivalent JOSE/signature algorithm.
     */
    public function toSignatureAlgorithm(): Algorithm
    {
        return match ($this) {
            self::ES256 => Algorithm::ES256,
            self::ES384 => Algorithm::ES384,
            self::ES512 => Algorithm::ES512,
            self::EdDSA => Algorithm::EdDSA,
            self::RS256 => Algorithm::RS256,
        };
    }
}
