<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Codec\Hex;
use RoundlyConsulting\Crypto\Codec\InvalidEncodingException;

it('round-trips random bytes', function (): void {
    foreach (range(1, 20) as $length) {
        $bytes = random_bytes($length);

        expect(Hex::decode(Hex::encode($bytes)))->toBe($bytes);
    }
});

it('encodes to lower-case hexadecimal', function (): void {
    expect(Hex::encode("\x00\xFF\x10"))->toBe('00ff10');
});

it('encodes and decodes the empty string', function (): void {
    expect(Hex::encode(''))->toBe('')
        ->and(Hex::decode(''))->toBe('');
});

it('rejects an odd-length string', function (): void {
    Hex::decode('abc');
})->throws(InvalidEncodingException::class);

it('rejects non-hexadecimal characters', function (): void {
    Hex::decode('zz');
})->throws(InvalidEncodingException::class);
