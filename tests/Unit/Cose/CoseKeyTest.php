<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Cose\CoseKey;
use RoundlyConsulting\Crypto\Cose\MalformedCborException;
use RoundlyConsulting\Crypto\Cose\UnsupportedAlgorithmException;
use RoundlyConsulting\Crypto\Signature\Algorithm;
use RoundlyConsulting\Crypto\Signature\Key\EcKey;

it('parses each supported COSE key type', function (string $name, Algorithm $algorithm): void {
    $key = CoseKey::fromCbor(coseBytes($name));

    expect($key->algorithm())->toBe($algorithm);
})->with([
    'ES256' => ['es256', Algorithm::ES256],
    'RS256' => ['rs256', Algorithm::RS256],
    'EdDSA' => ['eddsa', Algorithm::EdDSA],
]);

it('parses P-384 and P-521 EC2 keys from committed coordinates', function (string $name, int $crv, int $alg, Algorithm $algorithm): void {
    $vector = cryptoVectors()[$name];
    $key = CoseKey::fromCbor(coseCbor([
        1 => 2,
        3 => $alg,
        -1 => $crv,
        -2 => hex2bin($vector['x']),
        -3 => hex2bin($vector['y']),
    ]));

    expect($key->algorithm())->toBe($algorithm)
        ->and((new RoundlyConsulting\Crypto\Signature\KeyVerifier)->verify($key, hex2bin($vector['message']), hex2bin($vector['sig_raw'])))->toBeTrue();
})->with([
    'ES384/P-384' => ['es384', 2, -35, Algorithm::ES384],
    'ES512/P-521' => ['es512', 3, -36, Algorithm::ES512],
]);

it('rejects a P-384 key presented with the ES256 algorithm', function (): void {
    CoseKey::fromCbor(coseCbor([1 => 2, 3 => -7, -1 => 2, -2 => str_repeat("\x01", 48), -3 => str_repeat("\x02", 48)]));
})->throws(UnsupportedAlgorithmException::class);

it('rejects an unknown COSE algorithm identifier', function (): void {
    CoseKey::fromCbor(coseCbor([1 => 2, 3 => -999, -1 => 1, -2 => str_repeat("\x01", 32), -3 => str_repeat("\x02", 32)]));
})->throws(UnsupportedAlgorithmException::class);

it('rejects an unsupported key type', function (): void {
    CoseKey::fromCbor(coseCbor([1 => 9, 3 => -7]));
})->throws(UnsupportedAlgorithmException::class);

it('rejects an EC2 key that is not ES256', function (): void {
    CoseKey::fromCbor(coseCbor([1 => 2, 3 => -257, -1 => 1, -2 => str_repeat("\x01", 32), -3 => str_repeat("\x02", 32)]));
})->throws(UnsupportedAlgorithmException::class);

it('rejects an EC2 key on the wrong curve', function (): void {
    CoseKey::fromCbor(coseCbor([1 => 2, 3 => -7, -1 => 2, -2 => str_repeat("\x01", 32), -3 => str_repeat("\x02", 32)]));
})->throws(UnsupportedAlgorithmException::class);

it('rejects an OKP key that is not EdDSA', function (): void {
    CoseKey::fromCbor(coseCbor([1 => 1, 3 => -7, -1 => 6, -2 => str_repeat("\x01", 32)]));
})->throws(UnsupportedAlgorithmException::class);

it('rejects an OKP key on the wrong curve', function (): void {
    CoseKey::fromCbor(coseCbor([1 => 1, 3 => -8, -1 => 1, -2 => str_repeat("\x01", 32)]));
})->throws(UnsupportedAlgorithmException::class);

it('rejects an RSA key that is not RS256', function (): void {
    CoseKey::fromCbor(coseCbor([1 => 3, 3 => -7, -1 => str_repeat("\x01", 32), -2 => "\x01\x00\x01"]));
})->throws(UnsupportedAlgorithmException::class);

it('rejects a missing integer label', function (): void {
    CoseKey::fromCbor(coseCbor([3 => -7]));
})->throws(MalformedCborException::class);

it('rejects a missing binary field', function (): void {
    CoseKey::fromCbor(coseCbor([1 => 2, 3 => -7, -1 => 1, -2 => str_repeat("\x01", 32)]));
})->throws(MalformedCborException::class);

it('refuses a COSE key whose labels are text strings that look like integers', function (): void {
    $point = EcKey::generate()->coordinates();
    $text = static fn (string $value): string => chr(0x60 | strlen($value)).$value;

    // {"1": 2, "3": -7, "-1": 1, "-2": x, "-3": y} — every label a TEXT string.
    $cose = "\xA5".$text('1')."\x02".$text('3')."\x26".$text('-1')."\x01"
        .$text('-2')."\x58\x20".$point->x.$text('-3')."\x58\x20".$point->y;

    CoseKey::fromCbor($cose);
})->throws(MalformedCborException::class, 'text map key');

it('refuses a coordinate carried as a text string instead of a byte string', function (): void {
    $point = EcKey::generate()->coordinates();

    // x (label -2) as a 32-byte TEXT string (major type 3: 0x78 0x20).
    $cose = "\xA5\x01\x02\x03\x26\x20\x01\x21\x78\x20".$point->x."\x22\x58\x20".$point->y;

    expect(fn (): mixed => CoseKey::fromCbor($cose))
        ->toThrow(MalformedCborException::class);

    // An ASCII-only x is valid UTF-8, so only the TYPE check can catch it.
    $cose = "\xA5\x01\x02\x03\x26\x20\x01\x21\x78\x20".str_repeat('A', 32)."\x22\x58\x20".$point->y;

    expect(fn (): mixed => CoseKey::fromCbor($cose))
        ->toThrow(MalformedCborException::class, 'non-binary x');
});

it('refuses an integer label carried as a byte string', function (): void {
    // kty (label 1) as the byte string h'02' rather than the integer 2.
    CoseKey::fromCbor("\xA1\x01\x41\x02");
})->throws(MalformedCborException::class, 'non-integer kty');

it('refuses COSE bytes that are not exactly one map', function (string $hex, string $message): void {
    expect(fn (): mixed => CoseKey::fromCbor((string) hex2bin($hex)))
        ->toThrow(MalformedCborException::class, $message);
})->with([
    'an array' => ['8101', 'not a map'],
    'trailing bytes' => ['a000', 'trailing bytes'],
    'empty' => ['', 'unexpected end'],
]);
