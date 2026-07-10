<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Codec\Base64;
use RoundlyConsulting\Crypto\Codec\InvalidEncodingException;

it('round-trips arbitrary bytes through padded base64', function (): void {
    $bytes = random_bytes(40);

    expect(Base64::decode(Base64::encode($bytes)))->toBe($bytes);
});

it('produces the standard padded alphabet', function (): void {
    expect(Base64::encode('Many hands make light work.'))
        ->toBe('TWFueSBoYW5kcyBtYWtlIGxpZ2h0IHdvcmsu')
        ->and(Base64::encode("\xff\xfe"))->toBe('//4=');
});

it('decodes canonical padded input', function (): void {
    expect(Base64::decode('TWFu'))->toBe('Man')
        ->and(Base64::decode('TWE='))->toBe('Ma')
        ->and(Base64::decode('TQ=='))->toBe('M');
});

it('rejects non-canonical or malformed base64', function (string $text): void {
    Base64::decode($text);
})->with([
    'empty' => [''],
    'url-safe chars' => ['a-b_'],
    'missing padding' => ['TWE'],
    'wrong length' => ['TWFueQ'],
    'stray whitespace' => ["TWFu\n"],
    'non-alphabet' => ['TW*u'],
    'non-canonical tail' => ['TWE@'],
    'non-canonical padding bits' => ['YW=='],
])->throws(InvalidEncodingException::class);
