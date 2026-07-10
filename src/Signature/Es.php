<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Signature;

use RoundlyConsulting\Crypto\Signature\Ec\Der;
use RoundlyConsulting\Crypto\Signature\Key\EcKey;

/**
 * ECDSA on P-256 with SHA-256 (ES256) signer and verifier.
 *
 * Signatures are exchanged in the JOSE raw `r‖s` form; the raw↔DER conversion
 * ext-openssl needs is handled internally.
 */
final readonly class Es implements Signer, Verifier
{
    private const int COORDINATE_BYTES = 32;

    public function __construct(private EcKey $key) {}

    public function algorithm(): Algorithm
    {
        return Algorithm::ES256;
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

        $der = '';

        if (openssl_sign($message, $der, $this->key->key, OPENSSL_ALGO_SHA256) === false) {
            OpenSsl::drainErrors();

            throw KeyLoadException::signingFailed();
        }

        return Der::toRaw($der, self::COORDINATE_BYTES);
    }

    public function verify(string $message, string $signature): bool
    {
        // ES256 signatures are the fixed 64-byte raw form; convert to the DER
        // ext-openssl expects. A wrong-length value is not valid; a 64-byte one
        // always converts, so Der::fromRaw cannot throw here.
        if (strlen($signature) !== self::COORDINATE_BYTES * 2) {
            return false;
        }

        $der = Der::fromRaw($signature, self::COORDINATE_BYTES);

        $result = @openssl_verify($message, $der, $this->key->key, OPENSSL_ALGO_SHA256);

        if ($result === -1) {
            OpenSsl::drainErrors();
        }

        return $result === 1;
    }
}
