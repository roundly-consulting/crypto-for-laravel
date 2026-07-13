<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Asn1;

/**
 * The result of decoding a single leading DER element: the element and how many
 * bytes its TLV consumed — what a caller walking a concatenation of TLVs needs.
 */
final readonly class DerResult
{
    public function __construct(
        public DerElement $element,
        public int $bytesRead,
    ) {}
}
