<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\X509;

/**
 * An RFC 5280 §4.1.2.4 subject or issuer name — the attributes a caller actually
 * reads, as a DTO rather than OpenSSL's untyped shape array.
 *
 * A relative distinguished name may legally carry several values for the same
 * attribute (two CNs, say); OpenSSL returns those as an array and this DTO takes
 * the **first**. Attributes the certificate does not carry are `null`.
 */
final readonly class DistinguishedName
{
    public function __construct(
        public ?string $commonName = null,
        public ?string $organization = null,
        public ?string $organizationalUnit = null,
        public ?string $country = null,
        public ?string $state = null,
        public ?string $locality = null,
    ) {}

    /**
     * The present attributes in a fixed order, e.g. `CN=leaf.example, O=Acme, C=US`.
     */
    public function toString(): string
    {
        $parts = [
            'CN' => $this->commonName,
            'O' => $this->organization,
            'OU' => $this->organizationalUnit,
            'C' => $this->country,
            'ST' => $this->state,
            'L' => $this->locality,
        ];

        $present = [];

        foreach ($parts as $label => $value) {
            if ($value !== null) {
                $present[] = "{$label}={$value}";
            }
        }

        return implode(', ', $present);
    }
}
