<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Aead;

use RoundlyConsulting\Crypto\Exceptions\CryptoException;

/**
 * A key or nonce of the wrong length — a programming error, never a property of the data.
 */
final class InvalidAeadParameterException extends CryptoException
{
    public static function keyLength(int $length): self
    {
        return new self('An AES-256-GCM key must be '.Aes256Gcm::KEY_BYTES." bytes, [{$length}] given.");
    }

    public static function nonceLength(int $length): self
    {
        return new self('An AES-256-GCM nonce must be '.Aes256Gcm::NONCE_BYTES." bytes, [{$length}] given.");
    }

    public static function cipherUnavailable(): self
    {
        return new self('OpenSSL refused to encrypt with aes-256-gcm.');
    }
}
