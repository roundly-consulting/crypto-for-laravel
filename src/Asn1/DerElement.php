<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Asn1;

/**
 * One decoded DER element (a TLV).
 *
 * A structure, never a judgment: the element tells you the bytes said
 * `OCTET STRING`, or that a SEQUENCE has three children. What those bytes MEAN
 * — whether an OID is one you accept, whether a nonce matches — is the caller's,
 * exactly as {@see \RoundlyConsulting\Crypto\Cose\CborDecoder} decodes an
 * attestation object without knowing what attestation is.
 *
 * The typed readers (`oid()`, `integer()`, …) are the only place a tag is
 * interpreted, and each refuses a tag it does not admit rather than guessing.
 */
final readonly class DerElement
{
    /**
     * @param  list<self>  $children  the parsed children of a constructed element
     */
    public function __construct(
        public TagClass $class,
        public int $tag,
        public bool $constructed,
        public string $contents,
        private array $children = [],
    ) {}

    /**
     * The children of a constructed element, in encoding order.
     *
     * @return list<self>
     *
     * @throws MalformedDerException when the element is primitive
     */
    public function children(): array
    {
        if (! $this->constructed) {
            throw MalformedDerException::notConstructed($this->tag);
        }

        return $this->children;
    }

    /**
     * The first child carrying this CONTEXT-SPECIFIC tag, or null — how the
     * optional `[n]` fields of an X.509/PKIX structure are located.
     *
     * @throws MalformedDerException when the element is primitive
     */
    public function tagged(int $tag): ?self
    {
        foreach ($this->children() as $child) {
            if ($child->class === TagClass::ContextSpecific && $child->tag === $tag) {
                return $child;
            }
        }

        return null;
    }

    /**
     * The OBJECT IDENTIFIER as dotted decimal (UNIVERSAL 6).
     *
     * @throws MalformedDerException
     */
    public function oid(): string
    {
        $this->assertUniversal(6, 'OBJECT IDENTIFIER');

        $bytes = $this->contents;

        if ($bytes === '') {
            throw MalformedDerException::malformedContents('OBJECT IDENTIFIER', 'it is empty');
        }

        $subidentifiers = [];
        $value = 0;
        $started = false;

        for ($i = 0, $length = strlen($bytes); $i < $length; $i++) {
            $byte = ord($bytes[$i]);

            // A subidentifier may not begin with 0x80: that is a padded, and thus
            // non-canonical, base-128 encoding.
            if (! $started && $byte === 0x80) {
                throw MalformedDerException::malformedContents('OBJECT IDENTIFIER', 'a subidentifier is padded');
            }

            if ($value > (PHP_INT_MAX >> 7)) {
                throw MalformedDerException::malformedContents('OBJECT IDENTIFIER', 'a subidentifier overflows');
            }

            $value = ($value << 7) | ($byte & 0x7F);
            $started = true;

            if (($byte & 0x80) === 0) {
                $subidentifiers[] = $value;
                $value = 0;
                $started = false;
            }
        }

        if ($started) {
            throw MalformedDerException::malformedContents('OBJECT IDENTIFIER', 'the final subidentifier is unterminated');
        }

        // X.690 §8.19.4: the FIRST subidentifier packs the first two arcs as
        // X·40 + Y. It is base-128 like every other one — under arc 2, Y is
        // unbounded, so 2.999 is (999 + 80) spread over two octets, not one.
        $first = array_shift($subidentifiers);
        $arcs = match (true) {
            $first < 40 => [0, $first],
            $first < 80 => [1, $first - 40],
            default => [2, $first - 80],
        };

        array_push($arcs, ...$subidentifiers);

        return implode('.', $arcs);
    }

    /**
     * The INTEGER (UNIVERSAL 2). Values wider than 64 bits are returned as their
     * raw two's-complement bytes rather than being lossily coerced — an RSA
     * modulus is an INTEGER too.
     *
     * @throws MalformedDerException
     */
    public function integer(): int|string
    {
        $this->assertUniversal(2, 'INTEGER');

        $bytes = $this->contents;
        $length = strlen($bytes);

        if ($length === 0) {
            throw MalformedDerException::malformedContents('INTEGER', 'it is empty');
        }

        // X.690 §8.3.2: the first nine bits may not be all zero or all one — a
        // padded integer has more than one encoding, which DER forbids.
        if ($length > 1) {
            $lead = ord($bytes[0]);
            $next = ord($bytes[1]);

            if (($lead === 0x00 && ($next & 0x80) === 0) || ($lead === 0xFF && ($next & 0x80) !== 0)) {
                throw MalformedDerException::malformedContents('INTEGER', 'it is padded');
            }
        }

        if ($length > 8) {
            return $bytes;
        }

        $value = 0;

        for ($i = 0; $i < $length; $i++) {
            $value = ($value << 8) | ord($bytes[$i]);
        }

        // Sign-extend: eight bytes already land as a two's-complement 64-bit int.
        if ($length < 8 && (ord($bytes[0]) & 0x80) !== 0) {
            $value -= 1 << (8 * $length);
        }

        return $value;
    }

    /**
     * The OCTET STRING's bytes (UNIVERSAL 4), verbatim and uninterpreted.
     *
     * @throws MalformedDerException
     */
    public function octetString(): string
    {
        $this->assertUniversal(4, 'OCTET STRING');

        return $this->contents;
    }

    /**
     * The BOOLEAN (UNIVERSAL 1). DER admits exactly two encodings — 0x00 and
     * 0xFF — so a BER "any non-zero is true" byte is a rejection, not a `true`.
     *
     * @throws MalformedDerException
     */
    public function boolean(): bool
    {
        $this->assertUniversal(1, 'BOOLEAN');

        if (strlen($this->contents) !== 1) {
            throw MalformedDerException::malformedContents('BOOLEAN', 'it is not a single octet');
        }

        return match (ord($this->contents)) {
            0x00 => false,
            0xFF => true,
            default => throw MalformedDerException::malformedContents('BOOLEAN', 'DER encodes true as 0xFF'),
        };
    }

    /**
     * Whether this element is the ASN.1 NULL (UNIVERSAL 5). A predicate, so it
     * reports rather than throws.
     */
    public function isNull(): bool
    {
        return $this->class === TagClass::Universal && $this->tag === 5 && ! $this->constructed;
    }

    /**
     * @throws MalformedDerException
     */
    private function assertUniversal(int $tag, string $name): void
    {
        if ($this->class !== TagClass::Universal || $this->tag !== $tag || $this->constructed) {
            throw MalformedDerException::unexpectedTag($name, $this->tag);
        }
    }
}
