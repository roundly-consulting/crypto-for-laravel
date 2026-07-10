<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Signature;

use RoundlyConsulting\Crypto\Exceptions\CryptoException;

/**
 * Thrown when a key type does not match the requested algorithm, or when a
 * token's pinned algorithm does not match the verifier — i.e. any
 * algorithm-confusion attempt.
 */
final class AlgorithmMismatchException extends CryptoException
{
    public static function keyForAlgorithm(Algorithm $algorithm): self
    {
        return new self("The key type is not valid for algorithm [{$algorithm->value}].");
    }

    public static function pinning(): self
    {
        return new self('The token algorithm does not match the pinned algorithm.');
    }
}
