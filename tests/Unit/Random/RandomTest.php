<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Codec\Base32;
use RoundlyConsulting\Crypto\Codec\Base64Url;
use RoundlyConsulting\Crypto\Otp\Hotp;
use RoundlyConsulting\Crypto\Otp\Totp;
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

it('rejects a byte length above the maximum', function (): void {
    Bytes::generate(Bytes::MAXIMUM_LENGTH + 1);
})->throws(InvalidLengthException::class);

it('accepts a byte length at the maximum boundary', function (): void {
    expect(strlen(Bytes::generate(Bytes::MAXIMUM_LENGTH)))->toBe(Bytes::MAXIMUM_LENGTH);
});

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

it('rejects a token above the maximum length', function (): void {
    Token::urlSafe(Token::MAXIMUM_LENGTH + 1);
})->throws(InvalidLengthException::class);

it('rejects a custom-alphabet token above the maximum length', function (): void {
    Token::fromAlphabet('AB', Token::MAXIMUM_LENGTH + 1);
})->throws(InvalidLengthException::class);

it('generates a token from a custom alphabet', function (): void {
    $token = Token::fromAlphabet('AB', 50);

    expect(strlen($token))->toBe(50)
        ->and($token)->toMatch('/^[AB]+$/');
});

it('draws whole characters from a multibyte alphabet, never bytes', function (): void {
    $token = Token::fromAlphabet('äöü', 200);

    expect(mb_check_encoding($token, 'UTF-8'))->toBeTrue()
        ->and(mb_strlen($token, 'UTF-8'))->toBe(200)
        ->and($token)->toMatch('/^[äöü]+$/u')
        // 200 draws from three symbols: every one of them shows up.
        ->and(count(array_unique(mb_str_split($token, 1, 'UTF-8'))))->toBe(3);
});

it('draws emoji and mixed-width characters whole', function (): void {
    $token = Token::fromAlphabet('a€😀', 60);

    expect(mb_check_encoding($token, 'UTF-8'))->toBeTrue()
        ->and(mb_strlen($token, 'UTF-8'))->toBe(60);
});

it('rejects an alphabet that is not UTF-8 text', function (): void {
    Token::fromAlphabet("AB\xFF", 10);
})->throws(InvalidLengthException::class, 'UTF-8');

it('generates a numeric token of the exact length', function (): void {
    $token = Token::numeric(10);

    expect(strlen($token))->toBe(10)
        ->and($token)->toMatch('/^[0-9]+$/');
});

it('generates an alphanumeric token of the exact length', function (): void {
    $token = Token::alphanumeric(24);

    expect(strlen($token))->toBe(24)
        ->and($token)->toMatch('/^[0-9A-Za-z]+$/');
});

it('rejects a non-positive numeric length', function (): void {
    Token::numeric(0);
})->throws(InvalidLengthException::class);

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

it('generates canonical base32 secrets of varying length', function (int $chars): void {
    $secret = Secret::base32($chars);

    // Every generated secret must be exactly $chars and decode cleanly under the
    // strict (canonical) decoder — even at non-byte-aligned lengths.
    expect(strlen($secret))->toBe($chars);
    Base32::decode($secret);
})->with([16, 26, 40, 52, 63]);

it('only ever generates a secret the strict decoder and the OTP layer accept', function (int $chars): void {
    $secret = Secret::base32($chars);

    // A base32 string of 1, 3 or 6 characters mod 8 has a dangling character
    // that encodes no byte — no canonical encoding has that length — so such a
    // request rounds UP one character (never down: never less entropy).
    $expected = in_array($chars % 8, [1, 3, 6], true) ? $chars + 1 : $chars;

    expect(strlen($secret))->toBe($expected)
        ->and(Base32::encode(Base32::decode($secret)))->toBe($secret)
        ->and((new Totp)->codeAt($secret, 59))->toMatch('/^\d{6}$/')
        ->and((new Hotp)->at($secret, 0))->toMatch('/^\d{6}$/');
})->with([...range(1, 64), 4094, 4095, Secret::MAXIMUM_CHARS]);

it('rejects a non-positive secret length', function (): void {
    Secret::base32(0);
})->throws(InvalidLengthException::class);

it('rejects a secret length above the maximum', function (): void {
    Secret::base32(Secret::MAXIMUM_CHARS + 1);
})->throws(InvalidLengthException::class);

it('exposes the minimum token length constant', function (): void {
    expect(Token::MINIMUM_LENGTH)->toBe(32);
});
