<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Asn1;

/**
 * A strict X.690 DER reader.
 *
 * A PARSER, never a trust store — it turns bytes into structure and stops there,
 * exactly as {@see \RoundlyConsulting\Crypto\Cose\CborDecoder} does for CBOR. It
 * has no idea what a certificate extension, an attestation, or an authority is;
 * those are the caller's words, not this package's.
 *
 * It exists because `openssl_x509_parse()` pretty-prints unknown extensions into
 * lossy text, so anything that needs an extension's actual bytes needs a real DER
 * walk.
 *
 * **Strict, because the input is hostile.** DER is the canonical subset of BER,
 * and every laxity is a parser differential waiting to happen, so all of these are
 * rejected rather than accommodated:
 *
 * - indefinite lengths (BER only);
 * - non-minimal length encodings (a long form that fits the short form);
 * - non-minimal high-tag-number encodings;
 * - a declared length past the end of the buffer (never an over-read);
 * - trailing bytes after the top-level element ({@see decode()});
 * - a SEQUENCE/SET encoded primitive, or a BOOLEAN/INTEGER/OID/… encoded
 *   constructed;
 * - padded INTEGERs, padded OID subidentifiers, BER-lax BOOLEANs, non-empty NULLs.
 *
 * Work is bounded three ways — input size, nesting depth, and total element count
 * — so a nested-SEQUENCE bomb costs a typed exception, not the stack.
 */
final class DerDecoder
{
    /** An attacker-facing cap, checked before a single byte is parsed. */
    public const int MAX_INPUT_BYTES = 65536;

    /** Nesting cap (mirrors CborDecoder::MAX_DEPTH). */
    public const int MAX_DEPTH = 16;

    /** Total TLVs in one decode — a flat bomb is as cheap to write as a deep one. */
    public const int MAX_ELEMENTS = 4096;

    /**
     * Universal tags DER requires to be primitive (X.690 §8.x / §10.2).
     *
     * @var list<int>
     */
    private const array PRIMITIVE_UNIVERSAL_TAGS = [1, 2, 3, 4, 5, 6, 9, 10, 12, 13, 19, 20, 22, 23, 24, 26, 27, 28, 30];

    /**
     * Universal tags that are always constructed.
     *
     * @var list<int>
     */
    private const array CONSTRUCTED_UNIVERSAL_TAGS = [16, 17];

    /**
     * Decode exactly one element. Trailing bytes are an error — a certificate,
     * an extension value, or a signed structure is ONE element, and anything
     * after it is either a bug or a smuggling attempt.
     *
     * @throws MalformedDerException
     */
    public function decode(string $der): DerElement
    {
        $result = $this->decodeFirst($der);
        $trailing = strlen($der) - $result->bytesRead;

        if ($trailing !== 0) {
            throw MalformedDerException::trailingBytes($trailing);
        }

        return $result->element;
    }

    /**
     * Decode the leading element and report how many bytes it consumed, for
     * walking a concatenation of TLVs.
     *
     * @throws MalformedDerException
     */
    public function decodeFirst(string $der): DerResult
    {
        if (strlen($der) > self::MAX_INPUT_BYTES) {
            throw MalformedDerException::tooLarge(strlen($der), self::MAX_INPUT_BYTES);
        }

        $offset = 0;
        $elements = 0;

        $element = $this->readElement($der, $offset, 0, $elements);

        return new DerResult($element, $offset);
    }

    /**
     * @throws MalformedDerException
     */
    private function readElement(string $bytes, int &$offset, int $depth, int &$elements): DerElement
    {
        if ($depth > self::MAX_DEPTH) {
            throw MalformedDerException::tooDeep(self::MAX_DEPTH);
        }

        if (++$elements > self::MAX_ELEMENTS) {
            throw MalformedDerException::tooManyElements(self::MAX_ELEMENTS);
        }

        $identifier = $this->readByte($bytes, $offset);
        $class = TagClass::from(($identifier >> 6) & 0x03);
        $constructed = ($identifier & 0x20) !== 0;
        $tag = $this->readTag($bytes, $offset, $identifier & 0x1F);

        $this->assertFormAllowed($class, $tag, $constructed);

        $length = $this->readLength($bytes, $offset);
        $contents = $this->readBytes($bytes, $offset, $length);

        if ($class === TagClass::Universal && $tag === 5 && $contents !== '') {
            throw MalformedDerException::malformedContents('NULL', 'it carries content octets');
        }

        return new DerElement(
            class: $class,
            tag: $tag,
            constructed: $constructed,
            contents: $contents,
            children: $constructed ? $this->readChildren($contents, $depth, $elements) : [],
        );
    }

    /**
     * A constructed element's contents are themselves a run of TLVs, so they are
     * parsed eagerly: an element that was handed out has already been walked, and
     * cannot surprise a caller with a parse error from an innocent getter.
     *
     * @return list<DerElement>
     *
     * @throws MalformedDerException
     */
    private function readChildren(string $contents, int $depth, int &$elements): array
    {
        $offset = 0;
        $children = [];
        $length = strlen($contents);

        while ($offset < $length) {
            $children[] = $this->readElement($contents, $offset, $depth + 1, $elements);
        }

        return $children;
    }

    /**
     * The tag number: the low five bits, or the high-tag-number form when they are
     * all set. Android's key-description extension really does use tag 702, so the
     * multi-byte form is supported — minimally encoded, and only that.
     *
     * @throws MalformedDerException
     */
    private function readTag(string $bytes, int &$offset, int $low): int
    {
        if ($low !== 0x1F) {
            return $low;
        }

        $tag = 0;
        $read = 0;

        do {
            $byte = $this->readByte($bytes, $offset);

            if ($read === 0 && $byte === 0x80) {
                throw MalformedDerException::nonMinimalTag();
            }

            if (++$read > 4) {
                throw MalformedDerException::malformedContents('tag', 'it is wider than four octets');
            }

            $tag = ($tag << 7) | ($byte & 0x7F);
        } while (($byte & 0x80) !== 0);

        // Below 31 the tag fits the single-octet form, so the long form is padding.
        if ($tag < 0x1F) {
            throw MalformedDerException::nonMinimalTag();
        }

        return $tag;
    }

    /**
     * @throws MalformedDerException
     */
    private function readLength(string $bytes, int &$offset): int
    {
        $first = $this->readByte($bytes, $offset);

        if ($first < 0x80) {
            return $first;
        }

        if ($first === 0x80) {
            throw MalformedDerException::indefiniteLength();
        }

        if ($first === 0xFF) {
            throw MalformedDerException::reservedLength();
        }

        $count = $first & 0x7F;

        if ($count > 8) {
            throw MalformedDerException::malformedContents('length', 'it is wider than eight octets');
        }

        $chunk = $this->readBytes($bytes, $offset, $count);

        if (ord($chunk[0]) === 0x00) {
            throw MalformedDerException::nonMinimalLength();
        }

        $length = 0;

        for ($i = 0; $i < $count; $i++) {
            $length = ($length << 8) | ord($chunk[$i]);
        }

        // A negative value means the eight-byte length overflowed a PHP int; it is
        // astronomically past the input cap either way.
        if ($length < 0) {
            throw MalformedDerException::tooLarge(PHP_INT_MAX, self::MAX_INPUT_BYTES);
        }

        // The short form covers everything under 0x80, so the long form here is
        // a second encoding of the same length — exactly what DER forbids.
        if ($length < 0x80) {
            throw MalformedDerException::nonMinimalLength();
        }

        return $length;
    }

    /**
     * @throws MalformedDerException
     */
    private function readByte(string $bytes, int &$offset): int
    {
        if ($offset >= strlen($bytes)) {
            throw MalformedDerException::truncated();
        }

        return ord($bytes[$offset++]);
    }

    /**
     * The declared length is attacker-controlled, so it is checked against what is
     * actually left before a single byte is copied.
     *
     * @throws MalformedDerException
     */
    private function readBytes(string $bytes, int &$offset, int $length): string
    {
        if ($offset + $length > strlen($bytes)) {
            throw MalformedDerException::truncated();
        }

        $slice = substr($bytes, $offset, $length);
        $offset += $length;

        return $slice;
    }

    /**
     * @throws MalformedDerException
     */
    private function assertFormAllowed(TagClass $class, int $tag, bool $constructed): void
    {
        if ($class !== TagClass::Universal) {
            return;
        }

        if ($constructed && in_array($tag, self::PRIMITIVE_UNIVERSAL_TAGS, true)) {
            throw MalformedDerException::mustBePrimitive($tag);
        }

        if (! $constructed && in_array($tag, self::CONSTRUCTED_UNIVERSAL_TAGS, true)) {
            throw MalformedDerException::mustBeConstructed($tag);
        }
    }
}
