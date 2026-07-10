<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Signature\Key;

use RoundlyConsulting\Crypto\Signature\Algorithm;
use RoundlyConsulting\Crypto\Signature\Verifier;

/**
 * A public key that can verify signatures under exactly one algorithm.
 *
 * Implemented by {@see RsaKey}, {@see EcKey} and {@see OkpKey}, so a single
 * key-dispatching verifier can pin to the key's own algorithm.
 */
interface PublicKey
{
    public function algorithm(): Algorithm;

    /**
     * A verifier bound to this key and its algorithm.
     */
    public function verifier(): Verifier;
}
