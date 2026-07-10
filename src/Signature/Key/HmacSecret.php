<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Signature\Key;

use RoundlyConsulting\Crypto\Signature\WeakKeyException;
use SensitiveParameter;

/**
 * A validated shared secret for HS-family (HMAC) signatures.
 *
 * Four defences live in the factory: an empty secret is rejected; a value that
 * looks like a PEM is rejected so an RSA public key can never be smuggled in as
 * an HMAC key (the classic RS256→HS256 confusion attack); a secret under 256
 * bits is rejected as brute-forceable (RFC 7518 §3.2 requires HS256 keys of at
 * least the hash size); and a single-repeated-byte secret is rejected as
 * obviously low-entropy. The length guard measures bytes, not entropy, so the
 * value MUST be at least 32 *random* bytes.
 */
final readonly class HmacSecret
{
    private const int MIN_BYTES = 32;

    private function __construct(public string $value) {}

    /**
     * @throws WeakKeyException
     */
    public static function fromString(#[SensitiveParameter] string $secret): self
    {
        if ($secret === '') {
            throw WeakKeyException::emptySecret();
        }

        if (str_starts_with($secret, '-----BEGIN')) {
            throw WeakKeyException::pemAsSecret();
        }

        if (strlen($secret) < self::MIN_BYTES) {
            throw WeakKeyException::shortSecret();
        }

        // A single distinct byte (e.g. "aaaa…") satisfies the length guard but
        // carries no entropy — reject the most obvious low-entropy input.
        if (strlen(count_chars($secret, 3)) === 1) {
            throw WeakKeyException::lowEntropySecret();
        }

        return new self($secret);
    }
}
