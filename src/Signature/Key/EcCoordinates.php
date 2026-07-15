<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Signature\Key;

/**
 * The raw public point of an EC key: the affine X and Y coordinates as raw
 * big-endian bytes, each left-padded to exactly the curve's fixed coordinate
 * length ({@see EcKey::coordinateBytes()}).
 *
 * Fixed-length padding is not cosmetic: RFC 7518 §6.2.1.2 requires it, and a
 * truncated or short-padded coordinate changes a JWK thumbprint.
 */
final readonly class EcCoordinates
{
    public function __construct(
        public string $x,
        public string $y,
    ) {}
}
