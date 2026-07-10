<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Signature;

use RoundlyConsulting\Crypto\Hash\ConstantTime;
use RoundlyConsulting\Crypto\Signature\Key\HmacSecret;

/**
 * HMAC (HS256) signer and verifier over a validated shared secret.
 */
final readonly class Hs implements Signer, Verifier
{
    public function __construct(
        private HmacSecret $key,
        private Algorithm $algorithm = Algorithm::HS256,
    ) {
        if ($algorithm !== Algorithm::HS256) {
            throw AlgorithmMismatchException::keyForAlgorithm($algorithm);
        }
    }

    public function algorithm(): Algorithm
    {
        return $this->algorithm;
    }

    public function sign(string $message): string
    {
        return hash_hmac('sha256', $message, $this->key->value, true);
    }

    public function verify(string $message, string $signature): bool
    {
        return ConstantTime::equals($this->sign($message), $signature);
    }
}
