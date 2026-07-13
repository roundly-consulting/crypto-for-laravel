<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\X509;

use Carbon\CarbonImmutable;
use DateTimeInterface;
use OpenSSLCertificate;
use RoundlyConsulting\Crypto\Asn1\DerDecoder;
use RoundlyConsulting\Crypto\Asn1\DerElement;
use RoundlyConsulting\Crypto\Asn1\MalformedDerException;
use RoundlyConsulting\Crypto\Asn1\TagClass;
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
     * @param  array<string, Extension>  $extensions  keyed by OID
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
        private int $version,
        private bool $subjectIsEmpty,
        private array $extensions,
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
     * The extension carrying this OID, or null when the certificate has none.
     *
     * A FACT, and only a fact: you get the criticality flag and the RAW DER
     * inside the `extnValue` OCTET STRING. This package does not interpret those
     * bytes — decode them with {@see DerDecoder}
     * and rule on them in your own domain.
     *
     * The bytes come from a real DER walk of the certificate, not from
     * `openssl_x509_parse()`, whose extension values are pretty-printed text for
     * every OID it does not model — useless as bytes.
     *
     * RFC 5280 §4.2 forbids a repeated extension; should a certificate carry one
     * anyway, the FIRST occurrence is reported (as OpenSSL's own lookups do).
     */
    public function extension(string $oid): ?Extension
    {
        return $this->extensions[$oid] ?? null;
    }

    /**
     * Every extension, keyed by OID, in encoding order.
     *
     * @return array<string, Extension>
     */
    public function extensions(): array
    {
        return $this->extensions;
    }

    /**
     * The X.509 version number: 1, 2, or 3 (the encoded field is 0-based, and
     * absent means v1).
     */
    public function version(): int
    {
        return $this->version;
    }

    /**
     * Whether the subject Name is an empty SEQUENCE (RFC 5280 §4.1.2.6 — legal,
     * and what a TPM attestation-identity certificate does).
     *
     * `openssl_x509_parse()` cannot answer this faithfully: it drops RDNs it does
     * not model, so an unmodelled subject and an absent one look identical. The
     * DER walk can tell them apart.
     */
    public function subjectIsEmpty(): bool
    {
        return $this->subjectIsEmpty;
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
        $der = self::derFromPem($pem);

        // The structural walk runs on the certificate's OWN DER, because
        // openssl_x509_parse() pretty-prints unknown extensions into lossy text.
        // It is eager (the class's rule): a certificate that constructed has been
        // walked, so no getter can spring a parse error later. Whatever the walk
        // refuses lands as the same `unparseable()` an OpenSSL parse failure does
        // — one failure class for one question, "can this be read at all".
        try {
            $tbs = self::tbsCertificate($der);

            return new self(
                handle: $handle,
                pem: $pem,
                der: $der,
                subject: self::name($parsed['subject'] ?? null),
                issuer: self::name($parsed['issuer'] ?? null),
                dnsNames: self::dnsNamesFrom($parsed['extensions'] ?? null),
                serialNumber: $serial === null ? null : strtoupper($serial),
                signatureAlgorithm: self::text($parsed, 'signatureTypeLN'),
                notBefore: self::instantFrom($parsed, 'validFrom_time_t'),
                notAfter: self::instantFrom($parsed, 'validTo_time_t'),
                version: self::versionFrom($tbs),
                subjectIsEmpty: self::subjectIsEmptyIn($tbs),
                extensions: self::extensionsFrom($tbs),
            );
        } catch (MalformedDerException) {
            throw MalformedCertificateException::unparseable();
        }
    }

    /**
     * Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }.
     *
     * @throws MalformedDerException
     */
    private static function tbsCertificate(string $der): DerElement
    {
        return (new DerDecoder)->decode($der)->children()[0] ?? throw MalformedDerException::truncated();
    }

    /**
     * TBSCertificate ::= SEQUENCE { version [0] EXPLICIT DEFAULT v1, … } — an
     * absent version field means v1, and the encoded value is 0-based.
     *
     * @throws MalformedDerException|MalformedCertificateException
     */
    private static function versionFrom(DerElement $tbs): int
    {
        $field = $tbs->children()[0] ?? throw MalformedDerException::truncated();

        if ($field->class !== TagClass::ContextSpecific || $field->tag !== 0) {
            return 1;
        }

        $encoded = $field->children()[0] ?? throw MalformedDerException::truncated();
        $version = $encoded->integer();

        return is_int($version) && $version >= 0 && $version <= 2
            ? $version + 1
            : throw MalformedCertificateException::unparseable();
    }

    /**
     * The subject Name sits five fields after the optional version: serialNumber,
     * signature, issuer, validity, subject.
     *
     * @throws MalformedDerException
     */
    private static function subjectIsEmptyIn(DerElement $tbs): bool
    {
        $fields = $tbs->children();
        $first = $fields[0] ?? throw MalformedDerException::truncated();
        $offset = $first->class === TagClass::ContextSpecific && $first->tag === 0 ? 1 : 0;
        $subject = $fields[$offset + 4] ?? throw MalformedDerException::truncated();

        return $subject->children() === [];
    }

    /**
     * extensions [3] EXPLICIT SEQUENCE OF Extension ::= SEQUENCE {
     *     extnID OBJECT IDENTIFIER, critical BOOLEAN DEFAULT FALSE,
     *     extnValue OCTET STRING }
     *
     * @return array<string, Extension>
     *
     * @throws MalformedDerException
     */
    private static function extensionsFrom(DerElement $tbs): array
    {
        $wrapper = $tbs->tagged(3);

        if ($wrapper === null) {
            return [];
        }

        $list = $wrapper->children()[0] ?? throw MalformedDerException::truncated();
        $extensions = [];

        foreach ($list->children() as $entry) {
            $fields = $entry->children();
            $oid = ($fields[0] ?? throw MalformedDerException::truncated())->oid();

            // extnValue is the last field either way; the criticality BOOLEAN is
            // omitted when it is false, which is the DEFAULT.
            $value = ($fields[count($fields) - 1] ?? throw MalformedDerException::truncated())->octetString();
            $critical = count($fields) === 3 && $fields[1]->boolean();

            // A repeat is malformed per RFC 5280 §4.2; report the first, which is
            // what OpenSSL's own extension lookups do.
            $extensions[$oid] ??= new Extension($oid, $critical, $value);
        }

        return $extensions;
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
