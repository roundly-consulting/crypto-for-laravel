<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Testing;

use RoundlyConsulting\Crypto\Hash\HashAlgorithm;
use RoundlyConsulting\Crypto\Signature\Key\EcKey;
use RoundlyConsulting\Crypto\Signature\Key\RsaKey;
use RoundlyConsulting\Crypto\X509\Certificate;
use RoundlyConsulting\Crypto\X509\Chain;

/**
 * A freshly minted throwaway certificate chain plus the leaf's PRIVATE key, so a
 * test can sign a token with the leaf and hand the verifier the matching `x5c`.
 *
 * Everything here is ephemeral and worthless: never use it outside a test suite.
 */
final readonly class TestCertificateChain
{
    public function __construct(
        public Chain $chain,
        public EcKey|RsaKey $leafKey,
    ) {}

    public function leaf(): Certificate
    {
        return $this->chain->leaf();
    }

    public function root(): Certificate
    {
        return $this->chain->root();
    }

    /**
     * The chain as a JOSE `x5c` header value: standard base64 DER, leaf first.
     *
     * @return list<string>
     */
    public function x5c(): array
    {
        return array_map(
            static fn (Certificate $certificate): string => $certificate->base64(),
            $this->chain->certificates(),
        );
    }

    public function pemBundle(): string
    {
        return $this->chain->pemBundle();
    }

    /**
     * Fingerprints leaf → root — SHA-256 by default, like {@see Chain::fingerprints()}.
     * Pass {@see HashAlgorithm::Sha1} for a verifier that pins SHA-1.
     *
     * @return list<string>
     */
    public function fingerprints(HashAlgorithm $algorithm = HashAlgorithm::Sha256): array
    {
        return $this->chain->fingerprints($algorithm);
    }

    /**
     * The [intermediate … root] slice — what a pinning verifier compares, since
     * the leaf rotates and is never pinned. SHA-256 by default.
     *
     * @return list<string>
     */
    public function pinnedFingerprints(HashAlgorithm $algorithm = HashAlgorithm::Sha256): array
    {
        return array_slice($this->fingerprints($algorithm), 1);
    }
}
