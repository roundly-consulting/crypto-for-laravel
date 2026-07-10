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
    case HS384 = 'HS384';
    case HS512 = 'HS512';
    case RS256 = 'RS256';
    case RS384 = 'RS384';
    case RS512 = 'RS512';
    case ES256 = 'ES256';
    case ES384 = 'ES384';
    case ES512 = 'ES512';
    case EdDSA = 'EdDSA';

    /**
     * Whether the algorithm uses a public/private keypair rather than a shared
     * secret.
     */
    public function isAsymmetric(): bool
    {
        return ! $this->isHmac();
    }

    /**
     * Whether the algorithm is one of the HMAC (HS*) family.
     */
    public function isHmac(): bool
    {
        return match ($this) {
            self::HS256, self::HS384, self::HS512 => true,
            default => false,
        };
    }

    /**
     * The hash function backing the algorithm, as a PHP `hash_hmac`/`hash`
     * algorithm name. EdDSA hashes internally and has no separate digest.
     */
    public function hashName(): string
    {
        return match ($this) {
            self::HS256, self::RS256, self::ES256 => 'sha256',
            self::HS384, self::RS384, self::ES384 => 'sha384',
            self::HS512, self::RS512, self::ES512, self::EdDSA => 'sha512',
        };
    }

    /**
     * The matching `OPENSSL_ALGO_*` constant for the RSA/ECDSA families.
     */
    public function opensslAlgorithm(): int
    {
        return match ($this) {
            self::HS256, self::RS256, self::ES256 => OPENSSL_ALGO_SHA256,
            self::HS384, self::RS384, self::ES384 => OPENSSL_ALGO_SHA384,
            self::HS512, self::RS512, self::ES512, self::EdDSA => OPENSSL_ALGO_SHA512,
        };
    }
}
