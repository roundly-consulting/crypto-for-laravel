<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Aead;

use RoundlyConsulting\Crypto\Random\Bytes;
use SensitiveParameter;

/**
 * Authenticated encryption with associated data: AEAD_AES_256_GCM (RFC 5116 §5.2, NIST
 * SP 800-38D) — a 32-byte key, a 12-byte nonce and a 16-byte tag appended to the ciphertext.
 *
 * The associated data is authenticated, never encrypted: bind into it everything the
 * ciphertext must not be moved away from (a purpose, a record's identity), so a ciphertext
 * pasted into another context fails to open instead of decrypting there.
 *
 * `encrypt()` / `decrypt()` take the nonce explicitly (the RFC 5116 interface); `seal()` /
 * `open()` draw a random 96-bit nonce and carry it in front of the ciphertext. A random nonce
 * must not be reused under one key — keep a key below 2^32 seals (SP 800-38D §8.3). Holds no
 * key material of its own.
 */
final readonly class Aes256Gcm
{
    public const int KEY_BYTES = 32;

    public const int NONCE_BYTES = 12;

    public const int TAG_BYTES = 16;

    private const string CIPHER = 'aes-256-gcm';

    /**
     * The ciphertext with its tag appended.
     *
     * @throws InvalidAeadParameterException
     */
    public function encrypt(#[SensitiveParameter] string $key, string $nonce, #[SensitiveParameter] string $plaintext, string $associatedData = ''): string
    {
        self::assertParameters($key, $nonce);

        $tag = '';
        $ciphertext = openssl_encrypt($plaintext, self::CIPHER, $key, OPENSSL_RAW_DATA, $nonce, $tag, $associatedData, self::TAG_BYTES);

        // Unreachable with a valid key and nonce on a working OpenSSL; never return a bare tag.
        if ($ciphertext === false) {
            throw InvalidAeadParameterException::cipherUnavailable();
        }

        return $ciphertext.$tag;
    }

    /**
     * The plaintext — only when the tag authenticates the ciphertext, the nonce and the
     * associated data under the key.
     *
     * @throws DecryptionFailedException|InvalidAeadParameterException
     */
    public function decrypt(#[SensitiveParameter] string $key, string $nonce, string $ciphertext, string $associatedData = ''): string
    {
        self::assertParameters($key, $nonce);

        if (strlen($ciphertext) < self::TAG_BYTES) {
            throw new DecryptionFailedException;
        }

        $plaintext = openssl_decrypt(
            substr($ciphertext, 0, -self::TAG_BYTES), self::CIPHER, $key, OPENSSL_RAW_DATA, $nonce,
            substr($ciphertext, -self::TAG_BYTES), $associatedData,
        );

        if ($plaintext === false) {
            throw new DecryptionFailedException;
        }

        return $plaintext;
    }

    /**
     * `nonce ‖ ciphertext ‖ tag`, under a fresh random nonce.
     *
     * @throws InvalidAeadParameterException
     */
    public function seal(#[SensitiveParameter] string $key, #[SensitiveParameter] string $plaintext, string $associatedData = ''): string
    {
        $nonce = Bytes::generate(self::NONCE_BYTES);

        return $nonce.$this->encrypt($key, $nonce, $plaintext, $associatedData);
    }

    /**
     * Open what {@see seal()} produced.
     *
     * @throws DecryptionFailedException|InvalidAeadParameterException
     */
    public function open(#[SensitiveParameter] string $key, string $sealed, string $associatedData = ''): string
    {
        if (strlen($sealed) < self::NONCE_BYTES + self::TAG_BYTES) {
            throw new DecryptionFailedException;
        }

        return $this->decrypt($key, substr($sealed, 0, self::NONCE_BYTES), substr($sealed, self::NONCE_BYTES), $associatedData);
    }

    private static function assertParameters(#[SensitiveParameter] string $key, string $nonce): void
    {
        if (strlen($key) !== self::KEY_BYTES) {
            throw InvalidAeadParameterException::keyLength(strlen($key));
        }

        if (strlen($nonce) !== self::NONCE_BYTES) {
            throw InvalidAeadParameterException::nonceLength(strlen($nonce));
        }
    }
}
