<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Asn1;

/**
 * The two class bits of an ASN.1 identifier octet (X.690 §8.1.2.2).
 */
enum TagClass: int
{
    case Universal = 0;
    case Application = 1;
    case ContextSpecific = 2;
    case Private = 3;
}
