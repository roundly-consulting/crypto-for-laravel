<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\X509;

/**
 * One X.509 v3 extension, as it was actually encoded (RFC 5280 §4.1.2.9).
 *
 * A FACT: the OID, the criticality flag, and the raw DER carried inside the
 * `extnValue` OCTET STRING. This class does not interpret those bytes and never
 * will — what an Apple nonce, an Android key description, or a TCG SAN attribute
 * MEANS belongs to the caller's domain, decoded with
 * {@see \RoundlyConsulting\Crypto\Asn1\DerDecoder}.
 */
final readonly class Extension
{
    public function __construct(
        public string $oid,
        public bool $critical,
        /** The contents of extnValue's OCTET STRING — raw, uninterpreted DER. */
        public string $der,
    ) {}
}
