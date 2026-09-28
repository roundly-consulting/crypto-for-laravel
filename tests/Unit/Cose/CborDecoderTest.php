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
    'duplicate map key' => ['a2010101'.'02'],
    'non-minimal uint8' => ['1817'],
    'non-minimal uint16' => ['190018'],
    'non-minimal uint32' => ['1a00000100'],
    'non-minimal uint64' => ['1b0000000000010000'],
    'non-minimal negative int' => ['3817'],
]);

it('accepts a distinct-key map but rejects a repeated one', function (): void {
    expect((new CborDecoder)->decode(hex2bin('a201010202')))->toBe([1 => 1, 2 => 2]);

    (new CborDecoder)->decode(hex2bin('a2010101'.'02'));
})->throws(MalformedCborException::class, 'duplicate map key');

it('never turns a numeric-looking text key into an integer key', function (string $hex): void {
    // PHP stores the array key "1" as the integer 1, so a text label would be
    // indistinguishable from the COSE integer label it imitates.
    (new CborDecoder)->decode(hex2bin($hex));
})->throws(MalformedCborException::class, 'text map key')->with([
    '{"1": 2}' => ['a1613102'],
    '{"-1": 2}' => ['a1622d3102'],
    '{"3": -7}' => ['a1613326'],
]);

it('keeps a text key PHP leaves as a string', function (): void {
    // "01" and "-0" are not canonical integers, so PHP keeps them as strings.
    expect((new CborDecoder)->decode(hex2bin('a362303101622d3002616103')))
        ->toBe(['01' => 1, '-0' => 2, 'a' => 3]);
});

it('rejects a text string that is not UTF-8', function (): void {
    (new CborDecoder)->decode(hex2bin('62c328'));
})->throws(MalformedCborException::class, 'UTF-8');

it('rejects nesting deeper than the depth cap', function (): void {
    // 17 levels of single-element arrays (0x81) exceeds MAX_DEPTH (16).
    $bytes = str_repeat("\x81", CborDecoder::MAX_DEPTH + 1)."\x00";

    (new CborDecoder)->decode($bytes);
})->throws(MalformedCborException::class);

it('exposes the depth cap constant', function (): void {
    expect(CborDecoder::MAX_DEPTH)->toBe(16);
});
