<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Codec\Hex;
use RoundlyConsulting\Crypto\Facades\Crypto;
use RoundlyConsulting\Crypto\Hash\HashAlgorithm;
use RoundlyConsulting\Crypto\Hash\Hkdf;
use RoundlyConsulting\Crypto\Hash\InvalidHkdfParameterException;

/**
 * RFC 5869 Appendix A. Test cases 1–3 are HKDF-SHA-256, 4–7 HKDF-SHA-1; an empty salt is
 * "not provided" (HashLen zero bytes), exactly as the RFC defines it.
 *
 * @return array<string, array{HashAlgorithm, string, string, string, int, string}>
 */
function rfc5869Vectors(): array
{
    $range = static fn (int $from, int $to): string => implode('', array_map('chr', range($from, $to)));

    return [
        'A.1 sha256 basic' => [
            HashAlgorithm::Sha256, str_repeat("\x0b", 22), Hex::decode('000102030405060708090a0b0c'), Hex::decode('f0f1f2f3f4f5f6f7f8f9'), 42,
            '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865',
        ],
        'A.2 sha256 long inputs' => [
            HashAlgorithm::Sha256, $range(0x00, 0x4F), $range(0x60, 0xAF), $range(0xB0, 0xFF), 82,
            'b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87',
        ],
        'A.3 sha256 empty salt and info' => [
            HashAlgorithm::Sha256, str_repeat("\x0b", 22), '', '', 42,
            '8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8',
        ],
        'A.4 sha1 basic' => [
            HashAlgorithm::Sha1, str_repeat("\x0b", 11), Hex::decode('000102030405060708090a0b0c'), Hex::decode('f0f1f2f3f4f5f6f7f8f9'), 42,
            '085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2c22e422478d305f3f896',
        ],
        'A.6 sha1 empty salt and info' => [
            HashAlgorithm::Sha1, str_repeat("\x0b", 22), '', '', 42,
            '0ac1af7002b3d761d1e55298da9d0506b9ae52057220a306e07b6b87e8df21d0ea00033de03984d34918',
        ],
        'A.7 sha1 salt not provided' => [
            HashAlgorithm::Sha1, str_repeat("\x0c", 22), '', '', 42,
            '2c91117204d745f3500d636a62f64f0ab3bae548aa53d423b0d1f27ebba6f5e5673a081d70cce7acfc48',
        ],
    ];
}

it('derives the RFC 5869 output keying material', function (HashAlgorithm $algorithm, string $ikm, string $salt, string $info, int $length, string $okm): void {
    expect(Hex::encode((new Hkdf($algorithm))->derive($ikm, $length, $info, $salt)))->toBe($okm);
})->with(rfc5869Vectors());

it('defaults to SHA-256, an empty info and no salt', function (): void {
    $ikm = str_repeat("\x0b", 22);

    expect((new Hkdf)->derive($ikm, 42))
        ->toBe((new Hkdf(HashAlgorithm::Sha256))->derive($ikm, 42, '', ''))
        ->and(Hex::encode((new Hkdf)->derive($ikm, 42)))
        ->toBe('8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8');
});

it('separates subkeys by info, salt and algorithm', function (): void {
    $ikm = str_repeat("\x2a", 32);
    $base = (new Hkdf)->derive($ikm, 32, 'purpose-a');

    expect((new Hkdf)->derive($ikm, 32, 'purpose-b'))->not->toBe($base)
        ->and((new Hkdf)->derive($ikm, 32, 'purpose-a', 'salt'))->not->toBe($base)
        ->and((new Hkdf(HashAlgorithm::Sha512))->derive($ikm, 32, 'purpose-a'))->not->toBe($base);
});

it('matches the derivation the fleet already ships for SHA-384 and SHA-512', function (HashAlgorithm $algorithm): void {
    // No RFC vectors exist for these two; PHP's own HKDF is the reference the replaced
    // call sites used, so the helper must be byte-identical to it.
    $ikm = str_repeat("\x5c", 48);

    expect((new Hkdf($algorithm))->derive($ikm, 100, 'info', 'salt'))
        ->toBe(hash_hkdf($algorithm->value, $ikm, 100, 'info', 'salt'));
})->with([HashAlgorithm::Sha384, HashAlgorithm::Sha512]);

it('allows exactly 255 blocks of output and no more', function (HashAlgorithm $algorithm, int $hashLength): void {
    $hkdf = new Hkdf($algorithm);
    $max = 255 * $hashLength;

    expect(strlen($hkdf->derive('ikm', $max)))->toBe($max)
        ->and(fn () => $hkdf->derive('ikm', $max + 1))
        ->toThrow(InvalidHkdfParameterException::class, 'A length of ['.($max + 1)."] is outside 1–{$max} bytes");
})->with([
    'sha1' => [HashAlgorithm::Sha1, 20],
    'sha256' => [HashAlgorithm::Sha256, 32],
    'sha384' => [HashAlgorithm::Sha384, 48],
    'sha512' => [HashAlgorithm::Sha512, 64],
]);

it('refuses a zero or negative length instead of defaulting to one block', function (int $length): void {
    // hash_hkdf() reads 0 as "one hash length"; a derived key's size is never implicit here.
    expect(fn () => (new Hkdf)->derive('ikm', $length))
        ->toThrow(InvalidHkdfParameterException::class, "A length of [{$length}] is outside 1–8160 bytes");
})->with([0, -1]);

it('refuses empty input keying material', function (): void {
    expect(fn () => (new Hkdf)->derive('', 32))
        ->toThrow(InvalidHkdfParameterException::class, 'The input keying material must not be empty.');
});

it('is reachable from the facade and an injected manager', function (): void {
    $key = str_repeat("\x01", 32);

    // The cosmos vault fingerprint subkey, byte for byte.
    expect(Crypto::hkdf()->derive($key, 32, 'cosmos-vault-fingerprint'))
        ->toBe(hash_hkdf('sha256', $key, 32, 'cosmos-vault-fingerprint'))
        ->and(Crypto::hkdf(HashAlgorithm::Sha512)->derive($key, 64, 'info', 'salt'))
        ->toBe(hash_hkdf('sha512', $key, 64, 'info', 'salt'));
});
