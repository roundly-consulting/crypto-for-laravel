<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Signature;

/**
 * The JWS/COSE signature algorithms this package can sign or verify.
 *
 * Every signer and verifier is constructed for exactly one algorithm and pinned
 * to it per call — there is no "algorithm agility" switch — which is what makes
 * algorithm-confusion attacks structurally impossible. The backing value is the
 * JOSE `alg` header name.
 */
enum Algorithm: string
{
    case HS256 = 'HS256';
    case RS256 = 'RS256';
    case ES256 = 'ES256';
    case EdDSA = 'EdDSA';

    /**
     * Whether the algorithm uses a public/private keypair rather than a shared
     * secret.
     */
    public function isAsymmetric(): bool
    {
        return $this !== self::HS256;
    }
}
