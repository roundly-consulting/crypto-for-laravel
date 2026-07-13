<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Testing;

/**
 * The extension-shaped knobs a consumer's leaf certificate fixture needs — a DTO
 * rather than six more named parameters on {@see TestCertificates::chain()}.
 *
 * Everything here is a *minting* instruction, not a policy: this package has no
 * opinion on what an extension means, only on how to put one into a throwaway
 * certificate so a consumer can test its own reading of it.
 */
final readonly class TestLeafOptions
{
    /**
     * @param  array<string, string>  $rawExtensions  OID => the raw DER bytes to carry as the extension's value
     * @param  bool  $criticalRawExtensions  mark every raw extension critical
     * @param  list<string>  $extendedKeyUsageOids  EKU purposes, as dotted-decimal OIDs
     * @param  array<string, string>  $directoryNameSan  RDN (short name or OID) => value, emitted as a CRITICAL dirName SAN
     * @param  bool  $emptySubject  issue with an empty subject Name (RFC 5280 §4.1.2.6)
     * @param  string|null  $subjectOrganizationalUnit  an OU for the leaf's subject
     */
    public function __construct(
        public array $rawExtensions = [],
        public bool $criticalRawExtensions = false,
        public array $extendedKeyUsageOids = [],
        public array $directoryNameSan = [],
        public bool $emptySubject = false,
        public ?string $subjectOrganizationalUnit = null,
    ) {}
}
