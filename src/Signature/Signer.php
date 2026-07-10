<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Signature;

/**
 * Produces a detached signature over a message for exactly one algorithm.
 */
interface Signer
{
    public function algorithm(): Algorithm;

    /**
     * The raw signature bytes over the message, in the algorithm's wire form
     * (for ES256 this is the JOSE raw r‖s, not DER).
     */
    public function sign(string $message): string;
}
