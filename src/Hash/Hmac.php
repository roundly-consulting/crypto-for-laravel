<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Hash;

use RoundlyConsulting\Crypto\Signature\WeakKeyException;
use SensitiveParameter;

/**
 * Keyed-hash message authentication (HMAC) sign and constant-time verify.
 *
 * Used for webhook signatures, token peppers, and as the HMAC step inside the
 * OTP and HS-family signers. The secret is always passed per call and marked
 * sensitive; this class holds no key material of its own.
 *
 * The key may be any length, but never empty: anyone can compute a MAC under the
 * empty key. Signing with one throws; verifying with one fails closed. The 32-byte
 * floor belongs to {@see \RoundlyConsulting\Crypto\Signature\Key\HmacSecret}
 * (HS-family JOSE), not to this primitive, which also serves webhook secrets the
 * sender chose.
 */
final readonly class Hmac
{
    public function __construct(private HashAlgorithm $algorithm = HashAlgorithm::Sha256) {}

    /**
     * The raw-bytes HMAC of the message under the given key.
     *
     * @throws WeakKeyException when the key is empty
     */
    public function sign(string $message, #[SensitiveParameter] string $key): string
    {
        if ($key === '') {
            throw WeakKeyException::emptySecret();
        }

        return hash_hmac($this->algorithm->value, $message, $key, true);
    }

    /**
     * The lower-case hexadecimal HMAC of the message under the given key.
     *
     * @throws WeakKeyException when the key is empty
     */
    public function signHex(string $message, #[SensitiveParameter] string $key): string
    {
        if ($key === '') {
            throw WeakKeyException::emptySecret();
        }

        return hash_hmac($this->algorithm->value, $message, $key, false);
    }

    /**
     * Constant-time verify of a raw-bytes signature against a freshly computed one.
     * The submitted signature is sensitive too: a valid MAC authenticates its message.
     * An empty key never verifies: it is a missing secret, and anyone can forge a
     * MAC under it.
     */
    public function verify(string $message, #[SensitiveParameter] string $signature, #[SensitiveParameter] string $key): bool
    {
        return $key !== '' && ConstantTime::equals($this->sign($message, $key), $signature);
    }
}
