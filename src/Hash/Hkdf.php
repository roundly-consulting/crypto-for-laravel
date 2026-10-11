<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Hash;

use SensitiveParameter;

/**
 * HKDF (RFC 5869): extract-then-expand key derivation.
 *
 * Turns one root secret into independent per-purpose subkeys, so the same key never seals
 * a value AND MACs a fingerprint, or signs two kinds of document. The `info` string names
 * the purpose; the optional `salt` is a non-secret value (RFC 5869 §3.1), and an empty one
 * means "not provided" — HashLen zero bytes, exactly as the RFC defines it.
 *
 * The length is always explicit. `hash_hkdf()` reads 0 as "one hash length", which leaves
 * the size of a derived key implicit in the algorithm; here 0 is refused instead.
 */
final readonly class Hkdf
{
    public function __construct(private HashAlgorithm $algorithm = HashAlgorithm::Sha256) {}

    /**
     * `$length` raw bytes of output keying material: 1 to 255 × the hash's output length.
     *
     * @throws InvalidHkdfParameterException
     */
    public function derive(#[SensitiveParameter] string $ikm, int $length, string $info = '', string $salt = ''): string
    {
        if ($ikm === '') {
            throw InvalidHkdfParameterException::emptyKeyMaterial();
        }

        $max = 255 * $this->hashLength();

        if ($length < 1 || $length > $max) {
            throw InvalidHkdfParameterException::length($length, $max);
        }

        return hash_hkdf($this->algorithm->value, $ikm, $length, $info, $salt);
    }

    private function hashLength(): int
    {
        return match ($this->algorithm) {
            HashAlgorithm::Sha1 => 20,
            HashAlgorithm::Sha256 => 32,
            HashAlgorithm::Sha384 => 48,
            HashAlgorithm::Sha512 => 64,
        };
    }
}
