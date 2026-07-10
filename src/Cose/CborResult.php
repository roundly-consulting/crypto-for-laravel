<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Cose;

/**
 * The result of decoding a single leading CBOR item: the value and how many
 * bytes it consumed (used to locate the length-delimited COSE key that trails
 * attested credential data).
 */
final readonly class CborResult
{
    public function __construct(
        public mixed $value,
        public int $bytesConsumed,
    ) {}
}
