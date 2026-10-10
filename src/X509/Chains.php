<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\X509;

use RoundlyConsulting\Crypto\Codec\InvalidEncodingException;
use SensitiveParameter;

/**
 * `Crypto::x509()->chain()` — build a leaf → root {@see Chain} from an `x5c`
 * header, a list of PEMs, a concatenated PEM bundle, or parsed certificates.
 *
 * Pure delegation: the 10-certificate DoS cap and the typed errors are the
 * chain's own. A chain proves the math (`isLinked()`); the trust call is yours.
 */
final readonly class Chains
{
    /**
     * @param  list<string>  $x5c  standard base64 DER, leaf first
     *
     * @throws MalformedCertificateException|InvalidChainException|InvalidEncodingException
     */
    public function fromX5c(#[SensitiveParameter] array $x5c): Chain
    {
        return Chain::fromX5c($x5c);
    }

    /**
     * @param  list<string>  $pems  leaf first
     *
     * @throws MalformedCertificateException|InvalidChainException
     */
    public function fromPems(#[SensitiveParameter] array $pems): Chain
    {
        return Chain::fromPems($pems);
    }

    /**
     * @throws MalformedCertificateException|InvalidChainException
     */
    public function fromPemBundle(#[SensitiveParameter] string $bundle): Chain
    {
        return Chain::fromPemBundle($bundle);
    }

    /**
     * @param  list<Certificate>  $certificates  leaf first, root last
     *
     * @throws InvalidChainException
     */
    public function fromCertificates(array $certificates): Chain
    {
        return new Chain($certificates);
    }
}
