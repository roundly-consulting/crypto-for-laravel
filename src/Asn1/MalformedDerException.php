<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Asn1;

use RoundlyConsulting\Crypto\Exceptions\CryptoException;

/**
 * Thrown when DER input violates X.690's canonical rules or the decoder's caps.
 *
 * Every failure mode of {@see DerDecoder} and {@see DerElement} lands here: a
 * malformed, hostile, or merely BER-lax encoding must always be a typed
 * exception, never a PHP warning and never a silent reinterpretation.
 */
final class MalformedDerException extends CryptoException
{
    public static function truncated(): self
    {
        return new self('Malformed DER: the input ended inside an element.');
    }

    public static function indefiniteLength(): self
    {
        return new self('Malformed DER: indefinite-length encoding is BER, not DER.');
    }

    public static function nonMinimalLength(): self
    {
        return new self('Malformed DER: the length is not encoded in the minimal form DER requires.');
    }

    public static function reservedLength(): self
    {
        return new self('Malformed DER: the 0xFF length form is reserved.');
    }

    public static function nonMinimalTag(): self
    {
        return new self('Malformed DER: the tag number is not encoded in the minimal form DER requires.');
    }

    public static function trailingBytes(int $count): self
    {
        return new self("Malformed DER: {$count} trailing bytes after the top-level element.");
    }

    public static function tooDeep(int $depth): self
    {
        return new self("Malformed DER: nesting deeper than {$depth} levels.");
    }

    public static function tooLarge(int $bytes, int $max): self
    {
        return new self("Malformed DER: the input is {$bytes} bytes, over the {$max}-byte cap.");
    }

    public static function tooManyElements(int $max): self
    {
        return new self("Malformed DER: more than {$max} elements.");
    }

    public static function unexpectedTag(string $expected, int $actual): self
    {
        return new self("Malformed DER: expected {$expected}, found tag {$actual}.");
    }

    public static function notConstructed(int $tag): self
    {
        return new self("Malformed DER: tag {$tag} is primitive and has no children.");
    }

    public static function mustBePrimitive(int $tag): self
    {
        return new self("Malformed DER: universal tag {$tag} must be primitive in DER, not constructed.");
    }

    public static function mustBeConstructed(int $tag): self
    {
        return new self("Malformed DER: universal tag {$tag} must be constructed in DER, not primitive.");
    }

    public static function malformedContents(string $type, string $reason): self
    {
        return new self("Malformed DER: {$type} contents are invalid — {$reason}.");
    }
}
