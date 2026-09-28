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

    /**
     * A sane ceiling on the modulus size. Beyond this, verification cost (a
     * modular exponentiation over the modulus) grows without buying any security,
     * so an attacker-supplied oversized key is a denial-of-service vector rather
     * than a stronger key. 8192 bits is far above any real deployment.
     */
    private const int MAX_BITS = 8192;

    /** 8192 bits as bytes — the ceiling used to reject a raw modulus before it is even parsed. */
    private const int MAX_MODULUS_BYTES = self::MAX_BITS / 8;

    private function __construct(
        public OpenSSLAsymmetricKey $key,
        public bool $isPrivate,
    ) {}

    /**
     * Load an RSA public key from PEM text — never a `file://` path.
     *
     * @throws KeyLoadException|WeakKeyException
     */
    public static function public(string $pem): self
    {
        $key = OpenSsl::isPemText($pem) ? openssl_pkey_get_public($pem) : false;

        if ($key === false) {
            OpenSsl::drainErrors();

            throw KeyLoadException::unreadable('public');
        }

        self::assertRsaAtLeast2048($key, 'public');

        return new self($key, false);
    }

    /**
     * Load an RSA private key from PEM text — never a `file://` path.
     *
     * @throws KeyLoadException|WeakKeyException
     */
    public static function private(#[SensitiveParameter] string $pem): self
    {
        $key = OpenSsl::isPemText($pem) ? openssl_pkey_get_private($pem) : false;

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

        // Reject an oversized modulus before building or parsing a PEM, so a
        // pathologically large key can never reach the (expensive) parse/verify
        // path at all.
        if (strlen(ltrim($modulus, "\x00")) > self::MAX_MODULUS_BYTES) {
            throw WeakKeyException::rsaTooLarge(strlen(ltrim($modulus, "\x00")) * 8);
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

        // Cap generation too: a caller wiring the bit size to untrusted input
        // could otherwise burn unbounded CPU generating an absurdly large key.
        if ($bits > self::MAX_BITS) {
            throw WeakKeyException::rsaTooLarge($bits);
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

        self::persistPrivate($disk, $path, $key->privatePem());

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
        return (string) $this->details()['key'];
    }

    /**
     * The private (PKCS#8) PEM for this key — the single, typed export path for
     * private key material, for callers that persist a generated key somewhere
     * other than a Laravel disk (a filesystem path, a secret store, …).
     *
     * The returned string is secret: write it to owner-only storage, never log
     * it, and don't pass it anywhere it could end up in a stack trace.
     *
     * @throws KeyLoadException when this is a public key, or the export fails
     */
    public function privatePem(): string
    {
        if (! $this->isPrivate) {
            throw KeyLoadException::notPrivate('RSA');
        }

        return OpenSsl::exportPrivatePem($this->key);
    }

    /**
     * This key's raw public modulus (`n`), big-endian and minimal — no leading
     * zero octets, as RFC 7518 §6.3.1.1 requires.
     *
     * @throws KeyLoadException
     */
    public function modulus(): string
    {
        return self::minimal($this->member('n'));
    }

    /**
     * This key's raw public exponent (`e`), big-endian and minimal — no leading
     * zero octets, as RFC 7518 §6.3.1.2 requires.
     *
     * @throws KeyLoadException
     */
    public function exponent(): string
    {
        return self::minimal($this->member('e'));
    }

    public function verifier(): Verifier
    {
        return new Rs($this);
    }

    /**
     * One raw RSA public member from the key handle.
     *
     * @throws KeyLoadException
     */
    private function member(string $name): string
    {
        $value = $this->details()['rsa'][$name] ?? null;

        if (! is_string($value) || $value === '') {
            throw KeyLoadException::unreadable('public');
        }

        return $value;
    }

    /**
     * The key handle's OpenSSL details — the single place this class reads raw
     * key material, so the failure path is typed in exactly one spot.
     *
     * @return array<string, mixed>
     *
     * @throws KeyLoadException
     */
    private function details(): array
    {
        $details = openssl_pkey_get_details($this->key);

        if ($details === false) {
            OpenSsl::drainErrors();

            throw KeyLoadException::unreadable('public');
        }

        return $details;
    }

    /**
     * The minimal big-endian encoding of a positive integer. OpenSSL already
     * emits minimal bytes; stripping makes it a contract rather than a hope,
     * because a non-minimal `n` would change a JWK thumbprint.
     */
    private static function minimal(string $bytes): string
    {
        $stripped = ltrim($bytes, "\x00");

        return $stripped === '' ? "\x00" : $stripped;
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

        if ($bits > self::MAX_BITS) {
            throw WeakKeyException::rsaTooLarge($bits);
        }

        self::assertSaneExponent($details['rsa']['e'] ?? '');
    }

    /**
     * The public exponent must be an odd integer of at least 3. Zero, one, and
     * any even value (which cannot be a valid RSA exponent) are rejected; 65537
     * is the norm and 3 is the smallest safe value.
     *
     * @param  mixed  $exponent  the raw big-endian exponent bytes from openssl_pkey_get_details
     *
     * @throws WeakKeyException
     */
    private static function assertSaneExponent(mixed $exponent): void
    {
        $bytes = is_string($exponent) ? ltrim($exponent, "\x00") : '';

        // Empty (zero) or a single 0x01 byte (one) are both too small; an even
        // low byte means an even exponent. Everything else is odd and ≥ 3.
        $isEven = $bytes === '' || (ord($bytes[strlen($bytes) - 1]) & 1) === 0;

        if ($bytes === '' || $bytes === "\x01" || $isEven) {
            throw WeakKeyException::rsaBadExponent();
        }
    }
}
