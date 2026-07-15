<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\X509;

use Carbon\CarbonImmutable;
use DateTimeInterface;
use OpenSSLCertificate;
use RoundlyConsulting\Crypto\Codec\Base64;
use RoundlyConsulting\Crypto\Codec\InvalidEncodingException;
use RoundlyConsulting\Crypto\Hash\Digest;
use RoundlyConsulting\Crypto\Hash\HashAlgorithm;
use RoundlyConsulting\Crypto\Signature\Key\EcKey;
use RoundlyConsulting\Crypto\Signature\Key\PublicKey;
use RoundlyConsulting\Crypto\Signature\Key\RsaKey;

/**
 * A parsed X.509 certificate (RFC 5280).
 *
 * Every accessor is a FACT about the certificate. Nothing here is a trust ruling:
 * this class will tell you a certificate expired three years ago and hand you its
 * public key anyway. Which roots you trust, which fingerprints you pin, and
 * whether an expired certificate is acceptable are the caller's decisions —
 * crypto owns algorithms, the consumer owns trust.
 *
 * Parsing is eager: a `Certificate` that constructed successfully can never throw
 * a parse error later from an innocent-looking getter.
 */
final readonly class Certificate
{
    /** A cap on a single certificate's bytes — real certificates are a few KiB. */
    public const int MAX_CERTIFICATE_BYTES = 65536;

    /**
     * @param  list<string>  $dnsNames
     */
    private function __construct(
        private OpenSSLCertificate $handle,
        private string $pem,
        private string $der,
        private DistinguishedName $subject,
        private DistinguishedName $issuer,
        private array $dnsNames,
        private ?string $serialNumber,
        private ?string $signatureAlgorithm,
        private CarbonImmutable $notBefore,
        private CarbonImmutable $notAfter,
    ) {}

    /**
     * @throws MalformedCertificateException
     */
    public static function fromPem(string $pem): self
    {
        self::assertWithinCap(strlen($pem));

        return self::fromHandle(OpenSslX509::read($pem));
    }

    /**
     * @throws MalformedCertificateException
     */
    public static function fromDer(string $der): self
    {
        self::assertWithinCap(strlen($der));

        // openssl_x509_read() only accepts PEM (or a file path), so DER is
        // wrapped in the RFC 7468 textual encoding first.
        $pem = "-----BEGIN CERTIFICATE-----\n"
            .chunk_split(base64_encode($der), 64, "\n")
            ."-----END CERTIFICATE-----\n";

        return self::fromHandle(OpenSslX509::read($pem));
    }

    /**
     * An `x5c` entry: STANDARD (padded) base64 of the DER — RFC 7515 §4.1.6, not
     * base64url. The distinction matters: a base64url decoder silently mangles a
     * DER carrying `+` or `/`.
     *
     * @throws MalformedCertificateException|InvalidEncodingException
     */
    public static function fromBase64(string $base64): self
    {
        // Cap the ENCODED length before decoding: base64 is 4 bytes per 3.
        $max = intdiv(self::MAX_CERTIFICATE_BYTES * 4, 3) + 4;

        if (strlen($base64) > $max) {
            throw MalformedCertificateException::tooLarge(strlen($base64), $max);
        }

        return self::fromDer(Base64::decode($base64));
    }

    public function pem(): string
    {
        return $this->pem;
    }

    public function der(): string
    {
        return $this->der;
    }

    /**
     * The `x5c` form: standard, padded base64 of the DER.
     */
    public function base64(): string
    {
        return Base64::encode($this->der);
    }

    /**
     * The certificate fingerprint as LOWER-case hex, no colons — byte-identical
     * to `openssl_x509_fingerprint()`, which is a digest of the DER.
     *
     * The case is wire data: pinned fingerprints are stored and compared as
     * strings, so callers that need upper-case fold it themselves.
     */
    public function fingerprint(HashAlgorithm $algorithm = HashAlgorithm::Sha256): string
    {
        return (new Digest($algorithm))->hex($this->der);
    }

    /**
     * The certificate's public key, subject to this package's key policy (RSA
     * ≥ 2048 bits with a sane exponent, a supported curve).
     *
     * Certificate dates gate nothing here: an expired certificate still hands you
     * its key. Deciding what that means is yours.
     *
     * @throws MalformedCertificateException|\RoundlyConsulting\Crypto\Signature\KeyLoadException|\RoundlyConsulting\Crypto\Signature\WeakKeyException
     */
    public function publicKey(): PublicKey
    {
        $details = OpenSslX509::publicKeyDetails($this->handle);
        $pem = $details['key'] ?? null;
        $type = $details['type'] ?? null;

        return match (true) {
            $type === OPENSSL_KEYTYPE_RSA && is_string($pem) => RsaKey::public($pem),
            $type === OPENSSL_KEYTYPE_EC && is_string($pem) => EcKey::public($pem),
            default => throw MalformedCertificateException::unsupportedKeyType(),
        };
    }

    public function subject(): DistinguishedName
    {
        return $this->subject;
    }

    public function issuer(): DistinguishedName
    {
        return $this->issuer;
    }

    public function commonName(): ?string
    {
        return $this->subject->commonName;
    }

    /**
     * The `DNS:` entries of subjectAltName, wildcards verbatim. IP/email/URI SANs
     * are ignored by design.
     *
     * @return list<string>
     */
    public function dnsNames(): array
    {
        return $this->dnsNames;
    }

    /**
     * The serial number as upper-case hex.
     */
    public function serialNumber(): ?string
    {
        return $this->serialNumber;
    }

    public function signatureAlgorithm(): ?string
    {
        return $this->signatureAlgorithm;
    }

    public function notBefore(): CarbonImmutable
    {
        return $this->notBefore;
    }

    public function notAfter(): CarbonImmutable
    {
        return $this->notAfter;
    }

    /**
     * Whether $at falls inside the certificate's RFC 5280 validity PERIOD.
     *
     * This is a date fact, not a trust ruling. The leeway widens the window
     * symmetrically at BOTH ends — it exists for clock skew, and how much skew is
     * tolerable is the caller's policy, so crypto neither defaults it nor caps it.
     *
     * @param  int  $leewaySeconds  clock-skew tolerance, applied to both bounds
     *
     * @throws InvalidLeewayException when the leeway is negative
     */
    public function isValidAt(?DateTimeInterface $at = null, int $leewaySeconds = 0): bool
    {
        return ! $this->isExpiredAt($at, $leewaySeconds)
            && ! $this->isNotYetValidAt($at, $leewaySeconds);
    }

    /**
     * @throws InvalidLeewayException when the leeway is negative
     */
    public function isExpiredAt(?DateTimeInterface $at = null, int $leewaySeconds = 0): bool
    {
        self::assertLeeway($leewaySeconds);

        return self::instant($at) > $this->notAfter->getTimestamp() + $leewaySeconds;
    }

    /**
     * @throws InvalidLeewayException when the leeway is negative
     */
    public function isNotYetValidAt(?DateTimeInterface $at = null, int $leewaySeconds = 0): bool
    {
        self::assertLeeway($leewaySeconds);

        return self::instant($at) < $this->notBefore->getTimestamp() - $leewaySeconds;
    }

    /**
     * Is this certificate's signature made by $issuer's key? Pure math — it says
     * nothing about whether $issuer is an authority you should believe.
     */
    public function isSignedBy(self $issuer): bool
    {
        return OpenSslX509::signatureMatches($this->handle, $issuer->handle);
    }

    /**
     * Whether the certificate signed itself — the mathematical check, not a
     * subject-equals-issuer string compare (which a forger controls).
     */
    public function isSelfSigned(): bool
    {
        return $this->isSignedBy($this);
    }

    public function equals(self $other): bool
    {
        return hash_equals($this->der, $other->der);
    }

    /**
     * @throws MalformedCertificateException
     */
    private static function fromHandle(OpenSSLCertificate $handle): self
    {
        $pem = OpenSslX509::exportPem($handle);
        $parsed = OpenSslX509::parse($handle);
        $serial = self::text($parsed, 'serialNumberHex');

        return new self(
            handle: $handle,
            pem: $pem,
            der: self::derFromPem($pem),
            subject: self::name($parsed['subject'] ?? null),
            issuer: self::name($parsed['issuer'] ?? null),
            dnsNames: self::dnsNamesFrom($parsed['extensions'] ?? null),
            serialNumber: $serial === null ? null : strtoupper($serial),
            signatureAlgorithm: self::text($parsed, 'signatureTypeLN'),
            notBefore: self::instantFrom($parsed, 'validFrom_time_t'),
            notAfter: self::instantFrom($parsed, 'validTo_time_t'),
        );
    }

    /**
     * @throws MalformedCertificateException
     */
    private static function derFromPem(string $pem): string
    {
        $body = (string) preg_replace('/-----(BEGIN|END) CERTIFICATE-----|\s+/', '', $pem);
        $der = base64_decode($body, true);

        if ($der === false || $der === '') {
            throw MalformedCertificateException::exportFailed();
        }

        return $der;
    }

    /**
     * @throws MalformedCertificateException
     */
    private static function assertWithinCap(int $bytes): void
    {
        if ($bytes > self::MAX_CERTIFICATE_BYTES) {
            throw MalformedCertificateException::tooLarge($bytes, self::MAX_CERTIFICATE_BYTES);
        }
    }

    /**
     * @throws InvalidLeewayException
     */
    private static function assertLeeway(int $leewaySeconds): void
    {
        if ($leewaySeconds < 0) {
            throw InvalidLeewayException::negative($leewaySeconds);
        }
    }

    /**
     * The instant to evaluate against — the wall clock (honouring
     * `CarbonImmutable::setTestNow()`) unless the caller names one.
     */
    private static function instant(?DateTimeInterface $at): int
    {
        return $at?->getTimestamp() ?? CarbonImmutable::now()->getTimestamp();
    }

    private static function name(mixed $rdn): DistinguishedName
    {
        $rdn = is_array($rdn) ? $rdn : [];

        return new DistinguishedName(
            commonName: self::attribute($rdn, 'CN'),
            organization: self::attribute($rdn, 'O'),
            organizationalUnit: self::attribute($rdn, 'OU'),
            country: self::attribute($rdn, 'C'),
            state: self::attribute($rdn, 'ST'),
            locality: self::attribute($rdn, 'L'),
        );
    }

    /**
     * One RDN attribute. A multi-valued attribute (OpenSSL returns an array)
     * takes the first value.
     *
     * @param  array<array-key, mixed>  $rdn
     */
    private static function attribute(array $rdn, string $key): ?string
    {
        $value = $rdn[$key] ?? null;

        if (is_array($value)) {
            $value = $value[0] ?? null;
        }

        return is_string($value) && $value !== '' ? $value : null;
    }

    /**
     * @return list<string>
     */
    private static function dnsNamesFrom(mixed $extensions): array
    {
        if (! is_array($extensions) || ! is_string($extensions['subjectAltName'] ?? null)) {
            return [];
        }

        $names = [];

        foreach (explode(',', (string) $extensions['subjectAltName']) as $entry) {
            $entry = trim($entry);

            if (str_starts_with($entry, 'DNS:')) {
                $names[] = substr($entry, 4);
            }
        }

        return $names;
    }

    /**
     * @param  array<string, mixed>  $parsed
     */
    private static function text(array $parsed, string $key): ?string
    {
        $value = $parsed[$key] ?? null;

        return is_string($value) && $value !== '' ? $value : null;
    }

    /**
     * @param  array<string, mixed>  $parsed
     *
     * @throws MalformedCertificateException
     */
    private static function instantFrom(array $parsed, string $key): CarbonImmutable
    {
        $value = $parsed[$key] ?? null;

        if (! is_int($value)) {
            throw MalformedCertificateException::unparseable();
        }

        return CarbonImmutable::createFromTimestampUTC($value);
    }
}
