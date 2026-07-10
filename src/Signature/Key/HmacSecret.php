<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Signature\Key;

use RoundlyConsulting\Crypto\Random\Bytes;
use RoundlyConsulting\Crypto\Signature\KeyLoadException;
use RoundlyConsulting\Crypto\Signature\OpenSsl;
use RoundlyConsulting\Crypto\Signature\WeakKeyException;
use SensitiveParameter;

/**
 * A validated shared secret for HS-family (HMAC) signatures.
 *
 * Four defences live in the factory: an empty secret is rejected; any value that
 * carries public-key material is rejected so an RSA/EC public key can never be
 * smuggled in as an HMAC key (the classic RS256→HS256 confusion attack) — this
 * covers a PEM even behind leading whitespace or a UTF-8 BOM, and raw DER key
 * bytes; a secret under 256 bits is rejected as brute-forceable (RFC 7518 §3.2
 * requires HS256 keys of at least the hash size); and a single-repeated-byte
 * secret is rejected as obviously low-entropy. The length guard measures bytes,
 * not entropy — it is not a proof of randomness — so the value MUST be at least
 * 32 *random* bytes (generate one with the CSPRNG factory below).
 *
 * When ext-sodium is present the raw secret is best-effort wiped from memory when
 * the object is destroyed. PHP cannot guarantee wiping (copy-on-write may leave
 * other copies), so this is defence-in-depth, not a guarantee. The property is
 * intentionally not `readonly`: a readonly string cannot be zeroed in place.
 */
final class HmacSecret
{
    use ReadsKeyMaterial;

    private const int MIN_BYTES = 32;

    private function __construct(public string $value) {}

    /**
     * Best-effort wipe of the raw secret when ext-sodium is available. PHP cannot
     * guarantee memory wiping; this only reduces the window a secret lingers.
     */
    public function __destruct()
    {
        self::wipeSecret($this->value);
    }

    /**
     * @throws WeakKeyException
     */
    public static function fromString(#[SensitiveParameter] string $secret): self
    {
        if ($secret === '') {
            throw WeakKeyException::emptySecret();
        }

        if (self::carriesKeyMaterial($secret)) {
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

    /**
     * Generate a fresh CSPRNG secret of at least 256 bits.
     *
     * @throws WeakKeyException when fewer than 32 bytes are requested
     */
    public static function generate(int $bytes = self::MIN_BYTES): self
    {
        if ($bytes < self::MIN_BYTES) {
            throw WeakKeyException::shortSecret();
        }

        // The bytes come straight from the CSPRNG, so the fromString entropy
        // guards can be skipped — construct directly to avoid a spurious throw.
        return new self(Bytes::generate($bytes));
    }

    /**
     * Load a secret from a Laravel filesystem disk.
     *
     * @throws KeyLoadException when the file is missing or the disk is unreadable
     * @throws WeakKeyException when the stored secret fails the strength guards
     */
    public static function fromStorage(string $disk, string $path): self
    {
        return self::fromString(self::readFromStorage($disk, $path));
    }

    /**
     * Load a secret from the consumer's own config key.
     *
     * @throws KeyLoadException when the config value is missing, empty, or not a string
     * @throws WeakKeyException when the configured secret fails the strength guards
     */
    public static function fromConfig(string $key): self
    {
        return self::fromString(self::requireConfigString($key, config($key)));
    }

    /**
     * Load a secret from a disk path, generating and persisting a fresh one when
     * the file is missing. An existing-but-invalid secret is never overwritten —
     * it still throws.
     *
     * @throws KeyLoadException when the disk is unreadable
     * @throws WeakKeyException when an existing secret fails the strength guards
     */
    public static function fromStorageOrGenerate(string $disk, string $path, int $bytes = self::MIN_BYTES): self
    {
        if (self::storageHas($disk, $path)) {
            return self::fromStorage($disk, $path);
        }

        $secret = self::generate($bytes);

        self::persistPrivate($disk, $path, $secret->value);

        return $secret;
    }

    /**
     * Whether the value carries public-key material and so must never be accepted
     * as an HMAC secret. Catches a PEM even behind leading whitespace or a UTF-8
     * BOM, and raw DER key bytes (by wrapping them and re-parsing). A CSPRNG
     * secret never parses as a key, so this cannot reject legitimate material.
     */
    private static function carriesKeyMaterial(#[SensitiveParameter] string $secret): bool
    {
        // A textual PEM smuggle, robust to a leading BOM and/or whitespace.
        $text = str_starts_with($secret, "\xEF\xBB\xBF") ? substr($secret, 3) : $secret;

        if (str_starts_with(ltrim($text), '-----BEGIN')) {
            return true;
        }

        // A parseable public key in PEM form.
        if (@openssl_pkey_get_public($secret) !== false) {
            OpenSsl::drainErrors();

            return true;
        }

        OpenSsl::drainErrors();

        // Raw DER key bytes: wrap as SPKI PEM and see if OpenSSL accepts them.
        $pem = "-----BEGIN PUBLIC KEY-----\n".chunk_split(base64_encode($secret), 64, "\n").'-----END PUBLIC KEY-----';
        $isDer = @openssl_pkey_get_public($pem) !== false;

        OpenSsl::drainErrors();

        return $isDer;
    }
}
