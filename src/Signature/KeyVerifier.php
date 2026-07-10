<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Signature;

use RoundlyConsulting\Crypto\Signature\Ec\Der;
use RoundlyConsulting\Crypto\Signature\Key\EcKey;
use RoundlyConsulting\Crypto\Signature\Key\PublicKey;

/**
 * One-call signature verification that pins to a public key's own algorithm.
 *
 * This is the entry point WebAuthn and JOSE key-driven verification use: hand it
 * the parsed COSE/JWK public key, the signed data and the signature, and it
 * dispatches to the correct algorithm — the key chooses the algorithm, never a
 * caller-supplied header. ECDSA signatures are accepted in either the DER form
 * WebAuthn delivers or the raw `r‖s` form; other algorithms use their native
 * wire form.
 */
final class KeyVerifier
{
    public function verify(PublicKey $key, string $message, string $signature): bool
    {
        if ($key instanceof EcKey) {
            $signature = $this->normaliseEcdsa($signature, $key->coordinateBytes());

            if ($signature === null) {
                return false;
            }
        }

        return $key->verifier()->verify($message, $signature);
    }

    /**
     * Normalise an ECDSA signature to the raw `r‖s` form {@see Es} expects,
     * accepting DER (WebAuthn) or an already-raw value at the key's own
     * coordinate size.
     */
    private function normaliseEcdsa(string $signature, int $coordinateBytes): ?string
    {
        if (Der::isValid($signature)) {
            try {
                return Der::toRaw($signature, $coordinateBytes);
            } catch (InvalidSignatureException) {
                return null;
            }
        }

        return strlen($signature) === $coordinateBytes * 2 ? $signature : null;
    }
}
