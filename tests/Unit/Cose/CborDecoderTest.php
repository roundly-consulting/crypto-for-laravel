<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Cose\CborDecoder;
use RoundlyConsulting\Crypto\Cose\MalformedCborException;

it('decodes the supported CBOR item types', function (string $hex, mixed $expected): void {
    expect((new CborDecoder)->decode(hex2bin($hex)))->toBe($expected);
})->with([
    'zero' => ['00', 0],
    'small uint' => ['17', 23],
    'uint8' => ['1818', 24],
    'uint16' => ['190100', 256],
    'uint32' => ['1a00010000', 65536],
    'uint64' => ['1b0000000100000000', 4294967296],
    'negative -1' => ['20', -1],
    'negative -24' => ['37', -24],
    'byte string' => ['420102', "\x01\x02"],
    'text string' => ['626162', 'ab'],
    'array' => ['83010203', [1, 2, 3]],
    'map' => ['a10102', [1 => 2]],
    'false' => ['f4', false],
    'true' => ['f5', true],
    'null' => ['f6', null],
]);

it('reports how many bytes a leading item consumed', function (): void {
    $result = (new CborDecoder)->decodeFirst("\x01\xff\xff");

    expect($result->value)->toBe(1)
        ->and($result->bytesConsumed)->toBe(1);
});

it('rejects malformed CBOR', function (string $hex): void {
    (new CborDecoder)->decode(hex2bin($hex));
})->throws(MalformedCborException::class)->with([
    'trailing bytes' => ['0000'],
    'truncated multi-byte length' => ['18'],
    'unexpected end' => [''],
    'indefinite length' => ['5f'],
    'float' => ['fa3f800000'],
    'undefined simple' => ['f7'],
    'unsupported major type (tag)' => ['c0'],
    'length overflows the integer range' => ['1bffffffffffffffff'],
    'declared length exceeds input' => ['4201'],
    'array length exceeds input' => ['98ff'],
    'map length exceeds input' => ['b8ff'],
    'non int or string map key' => ['a1800100'],
]);

it('rejects nesting deeper than the depth cap', function (): void {
    // 17 levels of single-element arrays (0x81) exceeds MAX_DEPTH (16).
    $bytes = str_repeat("\x81", CborDecoder::MAX_DEPTH + 1)."\x00";

    (new CborDecoder)->decode($bytes);
})->throws(MalformedCborException::class);

it('exposes the depth cap constant', function (): void {
    expect(CborDecoder::MAX_DEPTH)->toBe(16);
});
