<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Hash;

use SensitiveParameter;

/**
 * Keyed-hash message authentication (HMAC) sign and constant-time verify.
 *
 * Used for webhook signatures, token peppers, and as the HMAC step inside the
 * OTP and HS-family signers. The secret is always passed per call and marked
 * sensitive; this class holds no key material of its own.
 */
final readonly class Hmac
{
    public function __construct(private HashAlgorithm $algorithm = HashAlgorithm::Sha256) {}

    /**
     * The raw-bytes HMAC of the message under the given key.
     */
    public function sign(string $message, #[SensitiveParameter] string $key): string
    {
        return hash_hmac($this->algorithm->value, $message, $key, true);
    }

    /**
     * The lower-case hexadecimal HMAC of the message under the given key.
     */
    public function signHex(string $message, #[SensitiveParameter] string $key): string
    {
        return hash_hmac($this->algorithm->value, $message, $key, false);
    }

    /**
     * Constant-time verify of a raw-bytes signature against a freshly computed one.
     * The submitted signature is sensitive too: a valid MAC authenticates its message.
     */
    public function verify(string $message, #[SensitiveParameter] string $signature, #[SensitiveParameter] string $key): bool
    {
        return ConstantTime::equals($this->sign($message, $key), $signature);
    }
}
