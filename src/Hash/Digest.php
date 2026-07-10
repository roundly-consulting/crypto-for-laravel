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
 */
final readonly class Digest
{
    public function __construct(private HashAlgorithm $algorithm = HashAlgorithm::Sha256) {}

    /**
     * The raw-bytes digest of the data.
     */
    public function raw(string $data): string
    {
        return hash($this->algorithm->value, $data, true);
    }

    /**
     * The lower-case hexadecimal digest of the data.
     */
    public function hex(string $data): string
    {
        return hash($this->algorithm->value, $data, false);
    }

    /**
     * A hexadecimal digest, HMAC'd with the pepper when one is supplied.
     *
     * A null, empty, or whitespace-only pepper means "no pepper" and falls back
     * to a plain hash; a real pepper is used verbatim (never trimmed).
     */
    public function withPepper(string $data, #[SensitiveParameter] ?string $pepper): string
    {
        return $pepper === null || trim($pepper) === ''
            ? hash($this->algorithm->value, $data, false)
            : hash_hmac($this->algorithm->value, $data, $pepper, false);
    }
}
