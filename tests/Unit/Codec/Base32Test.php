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

it('decodes case-insensitively and tolerates padding and whitespace', function (): void {
    expect(Base32::decode('mzxw 6ytb oi=='))->toBe('foobar')
        ->and(Base32::decode('MZXW6YTBOI'))->toBe(Base32::decode('mzxw6ytboi'));
});

it('rejects characters outside the alphabet', function (): void {
    // 0 and 1 are not in the base32 alphabet.
    Base32::decode('MZXW6YTB01');
})->throws(InvalidEncodingException::class);

it('decodes the reference secret to its expected key bytes', function (): void {
    expect(bin2hex(Base32::decode('ABCDEFGHIJKLMNOP')))->toBe('00443214c74254b635cf');
});

it('decodes whitespace-only input to an empty string', function (): void {
    expect(Base32::decode('   '))->toBe('');
});
