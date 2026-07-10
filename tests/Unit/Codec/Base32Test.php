<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Codec\Base32;
use RoundlyConsulting\Crypto\Codec\InvalidEncodingException;

it('round-trips random bytes', function (): void {
    foreach (range(1, 20) as $length) {
        $bytes = random_bytes($length);

        expect(Base32::decode(Base32::encode($bytes)))->toBe($bytes);
    }
});

it('encodes without padding over the RFC 4648 alphabet', function (): void {
    expect(Base32::encode('foobar'))->toBe('MZXW6YTBOI');
});

it('decodes the canonical RFC 4648 vector', function (): void {
    expect(Base32::decode('MZXW6YTBOI'))->toBe('foobar');
});

it('encodes and decodes the empty string to itself', function (): void {
    expect(Base32::encode(''))->toBe('')
        ->and(Base32::decode(''))->toBe('');
});

it('decodes case-insensitively', function (): void {
    expect(Base32::decode('MZXW6YTBOI'))->toBe(Base32::decode('mzxw6ytboi'))
        ->and(Base32::decode('mzxw6ytboi'))->toBe('foobar');
});

it('decodes the RFC 4648 section 10 padded vectors', function (string $encoded, string $decoded): void {
    expect(Base32::decode($encoded))->toBe($decoded);
})->with([
    ['', ''],
    ['MY======', 'f'],
    ['MZXQ====', 'fo'],
    ['MZXW6===', 'foo'],
    ['MZXW6YQ=', 'foob'],
    ['MZXW6YTB', 'fooba'],
    ['MZXW6YTBOI======', 'foobar'],
]);

it('rejects characters outside the alphabet', function (): void {
    // 0 and 1 are not in the base32 alphabet.
    Base32::decode('MZXW6YTB01');
})->throws(InvalidEncodingException::class);

it('rejects interior whitespace instead of stripping it', function (): void {
    Base32::decode('MZXW 6YTB');
})->throws(InvalidEncodingException::class);

it('rejects interior padding', function (): void {
    Base32::decode('MZ==XW6Y');
})->throws(InvalidEncodingException::class);

it('rejects an invalid padding length', function (): void {
    // Two '=' is never a valid base32 padding run (only 1/3/4/6 are).
    Base32::decode('MZXW6YTBOI==');
})->throws(InvalidEncodingException::class);

it('rejects a non-zero sub-byte remainder', function (): void {
    // 'MZXW6YTBOI' is canonical (trailing bits zero); flipping the last char to
    // 'OJ' sets a leftover bit and must be rejected as non-canonical.
    expect(Base32::decode('MZXW6YTBOI'))->toBe('foobar');
    Base32::decode('MZXW6YTBOJ');
})->throws(InvalidEncodingException::class);

it('rejects a dangling character that encodes no byte', function (): void {
    // A single trailing base32 char (5 bits) cannot complete a byte.
    Base32::decode('MZXW6YTBO');
})->throws(InvalidEncodingException::class);

it('decodes the reference secret to its expected key bytes', function (): void {
    expect(bin2hex(Base32::decode('ABCDEFGHIJKLMNOP')))->toBe('00443214c74254b635cf');
});

it('rejects whitespace-only input', function (): void {
    Base32::decode('   ');
})->throws(InvalidEncodingException::class);
