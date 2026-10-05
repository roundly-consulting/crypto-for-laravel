<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\X509;

use ArrayIterator;
use Countable;
use IteratorAggregate;
use RoundlyConsulting\Crypto\Codec\InvalidEncodingException;
use RoundlyConsulting\Crypto\Hash\HashAlgorithm;
use Traversable;

/**
 * An ordered leaf → root certificate chain.
 *
 * {@see isLinked()} proves the MATH: every certificate is signed by the next one
 * up. It is deliberately not called `verify()` or `isValid()` — it makes no
 * statement about trust, expiry, key usage, revocation, or whether the last
 * certificate is a root you have ever heard of. Pin the anchors yourself.
 *
 * @implements IteratorAggregate<int, Certificate>
 */
final readonly class Chain implements Countable, IteratorAggregate
{
    /**
     * A DoS cap on an attacker-supplied chain: an `x5c` header is whatever the
     * token said, and every certificate costs a parse.
     */
    public const int MAX_CERTIFICATES = 10;

    /** @var list<Certificate> */
    private array $certificates;

    /**
     * @param  list<Certificate>  $certificates  leaf first, root last
     *
     * @throws InvalidChainException when the chain is empty, over the cap, not a list, or holds anything but certificates
     */
    public function __construct(array $certificates)
    {
        self::assertListOf($certificates, static fn (mixed $entry): bool => $entry instanceof Certificate, 'certificate');

        $this->certificates = $certificates;
    }

    /**
     * @param  list<string>  $pems
     *
     * @throws MalformedCertificateException|InvalidChainException
     */
    public static function fromPems(array $pems): self
    {
        self::assertListOf($pems, is_string(...), 'string');

        return new self(array_map(Certificate::fromPem(...), $pems));
    }

    /**
     * A JOSE `x5c` header value: standard (padded) base64 of each DER, leaf first
     * — RFC 7515 §4.1.6.
     *
     * @param  list<string>  $x5c
     *
     * @throws MalformedCertificateException|InvalidChainException|InvalidEncodingException
     */
    public static function fromX5c(array $x5c): self
    {
        self::assertListOf($x5c, is_string(...), 'string');

        return new self(array_map(Certificate::fromBase64(...), $x5c));
    }

    /**
     * Split a concatenated PEM bundle (leaf + chain) into its certificates.
     *
     * The blocks are counted BEFORE any of them is parsed, so an oversized bundle
     * costs a regex rather than a parse per certificate.
     *
     * @throws MalformedCertificateException|InvalidChainException
     */
    public static function fromPemBundle(string $bundle): self
    {
        preg_match_all(
            '/-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/s',
            $bundle,
            $matches,
        );

        return self::fromPems($matches[0]);
    }

    /**
     * @return list<Certificate>
     */
    public function certificates(): array
    {
        return $this->certificates;
    }

    /**
     * @throws InvalidChainException
     */
    public function leaf(): Certificate
    {
        return $this->get(0);
    }

    /**
     * The LAST certificate — not "a trusted root". Whether it is an anchor you
     * accept is your decision, made elsewhere.
     *
     * @throws InvalidChainException
     */
    public function root(): Certificate
    {
        return $this->get(count($this->certificates) - 1);
    }

    /**
     * @throws InvalidChainException
     */
    public function get(int $index): Certificate
    {
        return $this->certificates[$index] ?? throw InvalidChainException::outOfRange($index);
    }

    public function count(): int
    {
        return count($this->certificates);
    }

    /**
     * @return Traversable<int, Certificate>
     */
    public function getIterator(): Traversable
    {
        return new ArrayIterator($this->certificates);
    }

    /**
     * Every certificate is signed by its successor. Pure math: no trust, no
     * dates, no revocation. A single self-signed certificate is trivially linked.
     */
    public function isLinked(): bool
    {
        $count = count($this->certificates);

        for ($i = 0; $i < $count - 1; $i++) {
            if (! $this->certificates[$i]->isSignedBy($this->certificates[$i + 1])) {
                return false;
            }
        }

        return true;
    }

    /**
     * Fingerprints in leaf → root order.
     *
     * @return list<string>
     */
    public function fingerprints(HashAlgorithm $algorithm = HashAlgorithm::Sha256): array
    {
        return array_map(
            static fn (Certificate $certificate): string => $certificate->fingerprint($algorithm),
            $this->certificates,
        );
    }

    public function pemBundle(): string
    {
        return implode('', array_map(
            static fn (Certificate $certificate): string => $certificate->pem(),
            $this->certificates,
        ));
    }

    /**
     * The entries must be a real list — leaf at 0, no gaps, no string keys —
     * of the expected type, checked before anything is parsed or indexed: an
     * `x5c` is whatever the token said, and a gap or a stray value would
     * otherwise surface later as an undefined index or a TypeError.
     *
     * @param  array<mixed>  $entries
     * @param  callable(mixed): bool  $accepts
     *
     * @throws InvalidChainException
     */
    private static function assertListOf(array $entries, callable $accepts, string $expected): void
    {
        self::assertCount(count($entries));

        if (! array_is_list($entries)) {
            throw InvalidChainException::notAList();
        }

        foreach ($entries as $index => $entry) {
            if (! $accepts($entry)) {
                throw InvalidChainException::invalidEntry($index, $expected);
            }
        }
    }

    /**
     * @throws InvalidChainException
     */
    private static function assertCount(int $count): void
    {
        if ($count === 0) {
            throw InvalidChainException::empty();
        }

        if ($count > self::MAX_CERTIFICATES) {
            throw InvalidChainException::tooLong($count);
        }
    }
}
