<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Cose;

/**
 * A deliberately minimal, defensive CBOR (RFC 8949) decoder.
 *
 * It supports only the subset WebAuthn attestation objects and COSE keys use:
 * unsigned/negative integers, byte strings, text strings, definite-length
 * arrays and maps, and the three simple values false/true/null. Everything else
 * — indefinite lengths, tags, floats, other simple values — is rejected. Depth
 * is capped and every declared length is bounds-checked against the remaining
 * input, so hostile input can never cause a fatal error or unbounded work.
 *
 * Byte strings and text strings both decode to PHP strings; a text string must
 * be valid UTF-8. A text map key PHP would store as an integer (`"1"`, `"-1"`)
 * is rejected, so a text label can never pass for the integer label it imitates.
 * Callers that must tell a byte string from a text string — a COSE_Key does —
 * read {@see self::decodeMapWithTypes()}.
 */
final class CborDecoder
{
    public const int MAX_DEPTH = 16;

    /**
     * Decode exactly one top-level item. Trailing bytes are rejected, which is
     * required for the attestationObject (a single CBOR map).
     *
     * @throws MalformedCborException
     */
    public function decode(string $bytes): mixed
    {
        $result = $this->decodeFirst($bytes);

        if ($result->bytesConsumed !== strlen($bytes)) {
            throw MalformedCborException::make('trailing bytes after top-level item');
        }

        return $result->value;
    }

    /**
     * Decode the first item and report how many bytes it consumed.
     *
     * @throws MalformedCborException
     */
    public function decodeFirst(string $bytes): CborResult
    {
        $offset = 0;
        $value = $this->readItem($bytes, $offset, 0);

        return new CborResult($value, $offset);
    }

    /**
     * Decode exactly one top-level MAP and report each value's CBOR major type
     * next to it — `[type, value]` per key — because a PHP string cannot say
     * whether it was a byte string (2) or a text string (3).
     *
     * @return array<int|string, array{int, mixed}>
     *
     * @throws MalformedCborException
     */
    public function decodeMapWithTypes(string $bytes): array
    {
        $offset = 0;
        $initial = $this->readByte($bytes, $offset);

        if ($initial >> 5 !== 5) {
            throw MalformedCborException::make('the top-level item is not a map');
        }

        $entries = $this->readMapEntries($bytes, $offset, $this->readLength($bytes, $offset, $initial & 0x1F), 0);

        if ($offset !== strlen($bytes)) {
            throw MalformedCborException::make('trailing bytes after top-level item');
        }

        return $entries;
    }

    /**
     * @throws MalformedCborException
     */
    private function readItem(string $bytes, int &$offset, int $depth): mixed
    {
        if ($depth > self::MAX_DEPTH) {
            throw MalformedCborException::make('maximum nesting depth exceeded');
        }

        $initial = $this->readByte($bytes, $offset);
        $major = $initial >> 5;
        $additional = $initial & 0x1F;

        return match ($major) {
            0 => $this->readLength($bytes, $offset, $additional),
            1 => -1 - $this->readLength($bytes, $offset, $additional),
            2 => $this->readBytes($bytes, $offset, $this->readLength($bytes, $offset, $additional)),
            3 => $this->readText($bytes, $offset, $this->readLength($bytes, $offset, $additional)),
            4 => $this->readArray($bytes, $offset, $this->readLength($bytes, $offset, $additional), $depth),
            5 => $this->readMap($bytes, $offset, $this->readLength($bytes, $offset, $additional), $depth),
            7 => $this->readSimple($additional),
            default => throw MalformedCborException::make('unsupported major type '.$major),
        };
    }

    private function readByte(string $bytes, int &$offset): int
    {
        if ($offset >= strlen($bytes)) {
            throw MalformedCborException::make('unexpected end of input');
        }

        return ord($bytes[$offset++]);
    }

    /**
     * Resolve the argument (length / integer value) from the additional-info bits.
     */
    private function readLength(string $bytes, int &$offset, int $additional): int
    {
        if ($additional < 24) {
            return $additional;
        }

        $count = match ($additional) {
            24 => 1,
            25 => 2,
            26 => 4,
            27 => 8,
            default => throw MalformedCborException::make('reserved or indefinite length'),
        };

        $chunk = $this->readBytes($bytes, $offset, $count);

        // An eight-byte argument with its top bit set does not fit a PHP int — shifting it
        // in would wrap negative.
        if ($count === 8 && ord($chunk[0]) >= 0x80) {
            throw MalformedCborException::make('length exceeds supported range');
        }

        $value = 0;

        foreach (str_split($chunk) as $byte) {
            $value = ($value << 8) | ord($byte);
        }

        // CTAP2 canonical CBOR requires the shortest encoding: a value that fits
        // in fewer bytes must use them. Rejecting the long form removes the
        // encoding malleability WebAuthn forbids.
        $minimum = match ($count) {
            1 => 24,
            2 => 0x100,
            4 => 0x10000,
            default => 0x100000000,
        };

        if ($value < $minimum) {
            throw MalformedCborException::make('non-canonical (non-shortest) integer encoding');
        }

        return $value;
    }

    private function readBytes(string $bytes, int &$offset, int $length): string
    {
        if ($length < 0 || $offset + $length > strlen($bytes)) {
            throw MalformedCborException::make('declared length exceeds remaining input');
        }

        $slice = substr($bytes, $offset, $length);
        $offset += $length;

        return $slice;
    }

    /**
     * RFC 8949 §3.1: a text string is UTF-8. Anything else is invalid CBOR, not
     * a byte string wearing the wrong major type.
     */
    private function readText(string $bytes, int &$offset, int $length): string
    {
        $text = $this->readBytes($bytes, $offset, $length);

        if (! mb_check_encoding($text, 'UTF-8')) {
            throw MalformedCborException::make('text string is not valid UTF-8');
        }

        return $text;
    }

    /**
     * @return list<mixed>
     */
    private function readArray(string $bytes, int &$offset, int $length, int $depth): array
    {
        if ($offset + $length > strlen($bytes)) {
            throw MalformedCborException::make('array length exceeds remaining input');
        }

        $items = [];

        for ($i = 0; $i < $length; $i++) {
            $items[] = $this->readItem($bytes, $offset, $depth + 1);
        }

        return $items;
    }

    /**
     * @return array<int|string, mixed>
     */
    private function readMap(string $bytes, int &$offset, int $length, int $depth): array
    {
        return array_map(
            static fn (array $entry): mixed => $entry[1],
            $this->readMapEntries($bytes, $offset, $length, $depth),
        );
    }

    /**
     * @return array<int|string, array{int, mixed}> key => [the value's major type, the value]
     */
    private function readMapEntries(string $bytes, int &$offset, int $length, int $depth): array
    {
        if ($offset + $length > strlen($bytes)) {
            throw MalformedCborException::make('map length exceeds remaining input');
        }

        $map = [];

        for ($i = 0; $i < $length; $i++) {
            $key = $this->readItem($bytes, $offset, $depth + 1);

            if (! is_int($key) && ! is_string($key)) {
                throw MalformedCborException::make('map keys must be integers or strings');
            }

            // PHP stores the string key "1" as the integer 1. A text label that
            // would land as an integer is indistinguishable from the integer
            // label it imitates, so it is refused rather than silently retyped.
            if (is_string($key) && (string) (int) $key === $key) {
                throw MalformedCborException::make('text map key would be read as an integer');
            }

            // Canonical CBOR forbids duplicate keys; without this a later value
            // would silently overwrite an earlier one, so one logical map could
            // have several byte encodings.
            if (array_key_exists($key, $map)) {
                throw MalformedCborException::make('duplicate map key');
            }

            // readItem() refuses an exhausted buffer itself, so the peek below
            // only ever names the type of a value that is really there.
            $type = isset($bytes[$offset]) ? ord($bytes[$offset]) >> 5 : -1;
            $map[$key] = [$type, $this->readItem($bytes, $offset, $depth + 1)];
        }

        return $map;
    }

    private function readSimple(int $additional): ?bool
    {
        return match ($additional) {
            20 => false,
            21 => true,
            22 => null,
            default => throw MalformedCborException::make('unsupported simple value or float'),
        };
    }
}
