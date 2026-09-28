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
 *
 * RFC 7518 §3.2 requires a key at least as long as the hash output: 32 bytes for
 * HS256 (which every {@see HmacSecret} already is), 48 for HS384 and 64 for
 * HS512. A shorter key is refused here, because verifiers that enforce the rule
 * reject every token it signs.
 */
final readonly class Hs implements Signer, Verifier
{
    /**
     * @throws AlgorithmMismatchException when the algorithm is not HS*
     * @throws WeakKeyException when the secret is shorter than the algorithm's hash output
     */
    public function __construct(
        private HmacSecret $key,
        private Algorithm $algorithm = Algorithm::HS256,
    ) {
        if (! $algorithm->isHmac()) {
            throw AlgorithmMismatchException::keyForAlgorithm($algorithm);
        }

        $minimum = strlen(hash($algorithm->hashName(), '', true));

        if (strlen($key->value) < $minimum) {
            throw WeakKeyException::shortSecretFor($algorithm, $minimum, strlen($key->value));
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
