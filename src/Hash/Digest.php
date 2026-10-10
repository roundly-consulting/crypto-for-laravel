<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Hash;

use SensitiveParameter;

/**
 * Deterministic one-way digests for at-rest lookups and cache keys.
 *
 * Deterministic by design: the same input always yields the same digest, which
 * is what makes a unique-index equality lookup possible. An optional pepper
 * switches the plain hash to an HMAC for defence-in-depth.
 *
 * The data is `#[SensitiveParameter]`: what gets digested for an at-rest lookup
 * is a token, a password or personal data, never something a stack trace needs.
 */
final readonly class Digest
{
    public function __construct(private HashAlgorithm $algorithm = HashAlgorithm::Sha256) {}

    /**
     * The raw-bytes digest of the data.
     */
    public function raw(#[SensitiveParameter] string $data): string
    {
        return hash($this->algorithm->value, $data, true);
    }

    /**
     * The lower-case hexadecimal digest of the data.
     */
    public function hex(#[SensitiveParameter] string $data): string
    {
        return hash($this->algorithm->value, $data, false);
    }

    /**
     * A hexadecimal digest, HMAC'd with the pepper when one is supplied.
     *
     * The plain-vs-keyed choice is explicit, never inferred from the pepper's
     * content: only `null` selects the plain digest. Any non-null pepper — even
     * whitespace or an empty string — is used verbatim as the HMAC key (never
     * trimmed), so a caller can never silently downgrade a keyed digest to an
     * unkeyed one by passing a blank string.
     */
    public function withPepper(#[SensitiveParameter] string $data, #[SensitiveParameter] ?string $pepper): string
    {
        return $pepper === null
            ? hash($this->algorithm->value, $data, false)
            : hash_hmac($this->algorithm->value, $data, $pepper, false);
    }
}
