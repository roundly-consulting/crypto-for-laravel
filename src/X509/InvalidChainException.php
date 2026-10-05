<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\X509;

use RoundlyConsulting\Crypto\Exceptions\CryptoException;

/**
 * Thrown when a certificate chain is structurally unusable: empty, longer than
 * the cap, not a list, holding an entry of the wrong type, or indexed out of
 * range.
 */
final class InvalidChainException extends CryptoException
{
    public static function empty(): self
    {
        return new self('A certificate chain must hold at least one certificate.');
    }

    public static function tooLong(int $count): self
    {
        $max = Chain::MAX_CERTIFICATES;

        return new self("The certificate chain holds {$count} certificates, over the cap of {$max}.");
    }

    public static function notAList(): self
    {
        return new self('A certificate chain must be a list, leaf first: indexed 0, 1, 2, … with no gaps.');
    }

    public static function invalidEntry(int $index, string $expected): self
    {
        return new self("The chain entry at index [{$index}] is not a {$expected}.");
    }

    public static function outOfRange(int $index): self
    {
        return new self("There is no certificate at index [{$index}] in this chain.");
    }
}
