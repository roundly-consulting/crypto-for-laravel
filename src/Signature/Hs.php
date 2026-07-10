<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Signature;

use RoundlyConsulting\Crypto\Hash\ConstantTime;
use RoundlyConsulting\Crypto\Signature\Key\HmacSecret;

/**
 * HMAC signer and verifier (HS256/HS384/HS512) over a validated shared secret.
 *
 * The construction guard rejects any asymmetric algorithm, so an HMAC secret can
 * never be pressed into service for RS/ES/EdDSA — one half of the defence against
 * algorithm-confusion.
 */
final readonly class Hs implements Signer, Verifier
{
    public function __construct(
        private HmacSecret $key,
        private Algorithm $algorithm = Algorithm::HS256,
    ) {
        if (! $algorithm->isHmac()) {
            throw AlgorithmMismatchException::keyForAlgorithm($algorithm);
        }
    }

    public function algorithm(): Algorithm
    {
        return $this->algorithm;
    }

    public function sign(string $message): string
    {
        return hash_hmac($this->algorithm->hashName(), $message, $this->key->value, true);
    }

    public function verify(string $message, string $signature): bool
    {
        return ConstantTime::equals($this->sign($message), $signature);
    }
}
