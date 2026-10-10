<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\X509;

use RoundlyConsulting\Crypto\Codec\InvalidEncodingException;
use SensitiveParameter;

/**
 * `Crypto::x509()` — parse a certificate from any of the three encodings it
 * arrives in, and reach the chain parsers.
 *
 * Pure delegation to {@see Certificate}'s factories. Like the module it fronts,
 * it reports facts and never rules on trust.
 */
final readonly class Certificates
{
    /**
     * @throws MalformedCertificateException
     */
    public function fromPem(#[SensitiveParameter] string $pem): Certificate
    {
        return Certificate::fromPem($pem);
    }

    /**
     * @throws MalformedCertificateException
     */
    public function fromDer(#[SensitiveParameter] string $der): Certificate
    {
        return Certificate::fromDer($der);
    }

    /**
     * One `x5c` entry: STANDARD padded base64 of the DER (RFC 7515 §4.1.6).
     *
     * @throws MalformedCertificateException|InvalidEncodingException
     */
    public function fromBase64(#[SensitiveParameter] string $base64): Certificate
    {
        return Certificate::fromBase64($base64);
    }

    public function chain(): Chains
    {
        return new Chains;
    }
}
