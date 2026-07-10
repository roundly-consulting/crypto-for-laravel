<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Signature\Key;

use RoundlyConsulting\Crypto\Signature\Algorithm;
use RoundlyConsulting\Crypto\Signature\EdDSA;
use RoundlyConsulting\Crypto\Signature\KeyLoadException;
use RoundlyConsulting\Crypto\Signature\Verifier;

/**
 * An Octet Key Pair (OKP) public key for EdDSA verification.
 *
 * Only the Ed25519 curve is supported; the key is the raw 32-byte Edwards
 * public key that ext-sodium verifies against.
 */
final readonly class OkpKey implements PublicKey
{
    private const int ED25519_BYTES = 32;

    /** @var non-empty-string */
    public string $publicKey;

    /**
     * @param  non-empty-string  $publicKey
     */
    private function __construct(string $publicKey)
    {
        $this->publicKey = $publicKey;
    }

    /**
     * @throws KeyLoadException when the key is not exactly 32 bytes
     */
    public static function ed25519(string $rawPublic): self
    {
        if (strlen($rawPublic) !== self::ED25519_BYTES) {
            throw KeyLoadException::unreadable('Ed25519 public');
        }

        return new self($rawPublic);
    }

    public function algorithm(): Algorithm
    {
        return Algorithm::EdDSA;
    }

    public function verifier(): Verifier
    {
        return new EdDSA($this);
    }
}
