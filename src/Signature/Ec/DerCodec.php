<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Signature\Ec;

use RoundlyConsulting\Crypto\Signature\InvalidSignatureException;

/**
 * `Crypto::ecDer()` — the ECDSA signature-encoding codec: raw `r‖s` (JOSE,
 * WebAuthn) ↔ ASN.1 DER (ext-openssl).
 *
 * It lives at the top of the facade rather than under a `signatures()` group
 * because it is the only signature-level helper that is not a signer; a group of
 * one would add a hop and nothing else. Pure delegation to {@see Der}.
 */
final readonly class DerCodec
{
    /**
     * @throws InvalidSignatureException when the raw signature is not 2 × $coordBytes long
     */
    public function fromRaw(string $rawRS, int $coordBytes = 32): string
    {
        return Der::fromRaw($rawRS, $coordBytes);
    }

    /**
     * @throws InvalidSignatureException when the DER is not a valid ECDSA signature
     */
    public function toRaw(string $der, int $coordBytes = 32): string
    {
        return Der::toRaw($der, $coordBytes);
    }

    /**
     * Whether the bytes are a well-formed, minimally-encoded ECDSA DER signature.
     */
    public function isValid(string $der): bool
    {
        return Der::isValid($der);
    }
}
