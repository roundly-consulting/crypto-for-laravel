<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Signature\Key;

use OpenSSLAsymmetricKey;
use RoundlyConsulting\Crypto\Signature\Algorithm;
use RoundlyConsulting\Crypto\Signature\KeyLoadException;
use RoundlyConsulting\Crypto\Signature\OpenSsl;
use RoundlyConsulting\Crypto\Signature\Rs;
use RoundlyConsulting\Crypto\Signature\Verifier;
use RoundlyConsulting\Crypto\Signature\WeakKeyException;
use SensitiveParameter;

/**
 * A validated RSA key for RS256 signing (private) or verification (public).
 *
 * Construction proves the PEM is a real RSA key of at least 2048 bits, so a
 * verifier can never be handed a non-RSA or undersized key — this typing is
 * part of what blocks algorithm confusion.
 */
final readonly class RsaKey implements PublicKey
{
    use ReadsKeyMaterial;

    private const int MIN_BITS = 2048;

    private function __construct(
        public OpenSSLAsymmetricKey $key,
        public bool $isPrivate,
    ) {}

    /**
     * Load an RSA public key from PEM.
     *
     * @throws KeyLoadException|WeakKeyException
     */
    public static function public(string $pem): self
    {
        $key = openssl_pkey_get_public($pem);

        if ($key === false) {
            OpenSsl::drainErrors();

            throw KeyLoadException::unreadable('public');
        }

        self::assertRsaAtLeast2048($key, 'public');

        return new self($key, false);
    }

    /**
     * Load an RSA private key from PEM.
     *
     * @throws KeyLoadException|WeakKeyException
     */
    public static function private(#[SensitiveParameter] string $pem): self
    {
        $key = openssl_pkey_get_private($pem);

        if ($key === false) {
            OpenSsl::drainErrors();

            throw KeyLoadException::unreadable('private');
        }

        self::assertRsaAtLeast2048($key, 'private');

        return new self($key, true);
    }

    /**
     * Build a public key from raw modulus and exponent bytes (as carried in a
     * COSE key or JWK).
     *
     * @throws KeyLoadException|WeakKeyException
     */
    public static function fromModulusExponent(string $modulus, string $exponent): self
    {
        if ($modulus === '' || $exponent === '') {
            throw KeyLoadException::unreadable('public');
        }

        return self::public(Asn1::rsaPublicKeyPem($modulus, $exponent));
    }

    /**
     * Generate a fresh RSA private key.
     *
     * @throws KeyLoadException|WeakKeyException
     */
    public static function generate(int $bits = 2048): self
    {
        if ($bits < self::MIN_BITS) {
            throw WeakKeyException::rsaTooSmall($bits);
        }

        $key = OpenSsl::generateKey([
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
            'private_key_bits' => $bits,
        ]);

        return new self($key, true);
    }

    /**
     * Load an RSA public key from a Laravel filesystem disk.
     *
     * @throws KeyLoadException|WeakKeyException
     */
    public static function publicFromStorage(string $disk, string $path): self
    {
        return self::public(self::readFromStorage($disk, $path));
    }

    /**
     * Load an RSA private key from a Laravel filesystem disk.
     *
     * @throws KeyLoadException|WeakKeyException
     */
    public static function privateFromStorage(string $disk, string $path): self
    {
        return self::private(self::readFromStorage($disk, $path));
    }

    /**
     * Load an RSA public key PEM from the consumer's own config key.
     *
     * @throws KeyLoadException|WeakKeyException
     */
    public static function publicFromConfig(string $key): self
    {
        return self::public(self::requireConfigString($key, config($key)));
    }

    /**
     * Load an RSA private key PEM from the consumer's own config key.
     *
     * @throws KeyLoadException|WeakKeyException
     */
    public static function privateFromConfig(string $key): self
    {
        return self::private(self::requireConfigString($key, config($key)));
    }

    /**
     * Load a private key from a disk path, generating and persisting a fresh one
     * (the private PEM) when the file is missing. Derive and persist the public
     * side separately with {@see publicPem()}. An existing-but-invalid key is
     * never overwritten — it still throws.
     *
     * @throws KeyLoadException|WeakKeyException
     */
    public static function fromStorageOrGenerate(string $disk, string $path, int $bits = 2048): self
    {
        if (self::storageHas($disk, $path)) {
            return self::privateFromStorage($disk, $path);
        }

        $key = self::generate($bits);

        self::persistPrivate($disk, $path, OpenSsl::exportPrivatePem($key->key));

        return $key;
    }

    public function algorithm(): Algorithm
    {
        return Algorithm::RS256;
    }

    /**
     * The public (SPKI) PEM derived from this key — persist it alongside a
     * generated private key so verifiers can load the public half.
     *
     * @throws KeyLoadException
     */
    public function publicPem(): string
    {
        $details = openssl_pkey_get_details($this->key);

        if ($details === false) {
            OpenSsl::drainErrors();

            throw KeyLoadException::unreadable('public');
        }

        return (string) $details['key'];
    }

    public function verifier(): Verifier
    {
        return new Rs($this);
    }

    /**
     * @throws KeyLoadException|WeakKeyException
     */
    private static function assertRsaAtLeast2048(OpenSSLAsymmetricKey $key, string $kind): void
    {
        $details = openssl_pkey_get_details($key);

        if ($details === false) {
            throw KeyLoadException::unreadable($kind);
        }

        if (($details['type'] ?? null) !== OPENSSL_KEYTYPE_RSA) {
            throw KeyLoadException::wrongType($kind, 'RSA');
        }

        $bits = (int) ($details['bits'] ?? 0);

        if ($bits < self::MIN_BITS) {
            throw WeakKeyException::rsaTooSmall($bits);
        }
    }
}
