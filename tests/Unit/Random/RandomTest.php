<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Codec\Base32;
use RoundlyConsulting\Crypto\Codec\Base64Url;
use RoundlyConsulting\Crypto\Random\Bytes;
use RoundlyConsulting\Crypto\Random\InvalidLengthException;
use RoundlyConsulting\Crypto\Random\Secret;
use RoundlyConsulting\Crypto\Random\Token;

it('generates random bytes of the requested length', function (): void {
    expect(strlen(Bytes::generate(16)))->toBe(16)
        ->and(Bytes::generate(16))->not->toBe(Bytes::generate(16));
});

it('rejects a non-positive byte length', function (): void {
    Bytes::generate(0);
})->throws(InvalidLengthException::class);

it('generates a url-safe token of the exact character length', function (): void {
    $token = Token::urlSafe(40);

    expect(strlen($token))->toBe(40)
        ->and($token)->toMatch('/^[A-Za-z0-9_-]+$/');
    // Decodes as valid base64url.
    Base64Url::decode($token);
});

it('rejects a token below the minimum length', function (): void {
    Token::urlSafe(16);
})->throws(InvalidLengthException::class);

it('generates a token from a custom alphabet', function (): void {
    $token = Token::fromAlphabet('AB', 50);

    expect(strlen($token))->toBe(50)
        ->and($token)->toMatch('/^[AB]+$/');
});

it('rejects an empty alphabet', function (): void {
    Token::fromAlphabet('', 10);
})->throws(InvalidLengthException::class);

it('rejects a non-positive alphabet length', function (): void {
    Token::fromAlphabet('ABC', 0);
})->throws(InvalidLengthException::class);

it('generates a base32 secret of the exact character length', function (): void {
    $secret = Secret::base32(32);

    expect(strlen($secret))->toBe(32);
    // Decodes cleanly over the base32 alphabet.
    Base32::decode($secret);
});

it('generates base32 secrets of varying length', function (int $chars): void {
    expect(strlen(Secret::base32($chars)))->toBe($chars);
})->with([16, 26, 52]);

it('rejects a non-positive secret length', function (): void {
    Secret::base32(0);
})->throws(InvalidLengthException::class);

it('exposes the minimum token length constant', function (): void {
    expect(Token::MINIMUM_LENGTH)->toBe(32);
});
