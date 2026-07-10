<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Signature;

use RoundlyConsulting\Crypto\Signature\Ec\Der;
use RoundlyConsulting\Crypto\Signature\Key\EcKey;

/**
 * ECDSA signer and verifier (ES256/ES384/ES512) on P-256, P-384, and P-521.
 *
 * The curve — and therefore the coordinate size and digest — is taken from the
 * key itself, never from a caller-supplied header. Signatures are exchanged in
 * the JOSE raw `r‖s` form; the raw↔DER conversion ext-openssl needs is handled
 * internally.
 */
final readonly class Es implements Signer, Verifier
{
    public function __construct(private EcKey $key) {}

    public function algorithm(): Algorithm
    {
        return $this->key->algorithm();
    }

    /**
     * @throws KeyLoadException when signing with a public key or OpenSSL fails
     * @throws InvalidSignatureException when the produced DER cannot be normalised
     */
    public function sign(string $message): string
    {
        if (! $this->key->isPrivate) {
            throw KeyLoadException::signingFailed();
        }

        $der = OpenSsl::sign($message, $this->key->key, $this->algorithm()->opensslAlgorithm());

        return Der::toRaw($der, $this->key->coordinateBytes());
    }

    public function verify(string $message, string $signature): bool
    {
        $coordinateBytes = $this->key->coordinateBytes();

        // ES signatures are the fixed-length raw `r‖s` form; convert to the DER
        // ext-openssl expects. A wrong-length value is not valid; a correct-length
        // one always converts, so Der::fromRaw cannot throw here.
        if (strlen($signature) !== $coordinateBytes * 2) {
            return false;
        }

        $der = Der::fromRaw($signature, $coordinateBytes);

        return OpenSsl::verify($message, $der, $this->key->key, $this->algorithm()->opensslAlgorithm());
    }
}
