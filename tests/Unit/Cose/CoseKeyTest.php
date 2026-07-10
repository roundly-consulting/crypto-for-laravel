<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Cose\CoseKey;
use RoundlyConsulting\Crypto\Cose\MalformedCborException;
use RoundlyConsulting\Crypto\Cose\UnsupportedAlgorithmException;
use RoundlyConsulting\Crypto\Signature\Algorithm;

it('parses each supported COSE key type', function (string $name, Algorithm $algorithm): void {
    $key = CoseKey::fromDecoded(coseMap($name));

    expect($key->algorithm())->toBe($algorithm);
})->with([
    'ES256' => ['es256', Algorithm::ES256],
    'RS256' => ['rs256', Algorithm::RS256],
    'EdDSA' => ['eddsa', Algorithm::EdDSA],
]);

it('rejects an unknown COSE algorithm identifier', function (): void {
    CoseKey::fromDecoded([1 => 2, 3 => -999, -1 => 1, -2 => str_repeat("\x01", 32), -3 => str_repeat("\x02", 32)]);
})->throws(UnsupportedAlgorithmException::class);

it('rejects an unsupported key type', function (): void {
    CoseKey::fromDecoded([1 => 9, 3 => -7]);
})->throws(UnsupportedAlgorithmException::class);

it('rejects an EC2 key that is not ES256', function (): void {
    CoseKey::fromDecoded([1 => 2, 3 => -257, -1 => 1, -2 => str_repeat("\x01", 32), -3 => str_repeat("\x02", 32)]);
})->throws(UnsupportedAlgorithmException::class);

it('rejects an EC2 key on the wrong curve', function (): void {
    CoseKey::fromDecoded([1 => 2, 3 => -7, -1 => 2, -2 => str_repeat("\x01", 32), -3 => str_repeat("\x02", 32)]);
})->throws(UnsupportedAlgorithmException::class);

it('rejects an OKP key that is not EdDSA', function (): void {
    CoseKey::fromDecoded([1 => 1, 3 => -7, -1 => 6, -2 => str_repeat("\x01", 32)]);
})->throws(UnsupportedAlgorithmException::class);

it('rejects an OKP key on the wrong curve', function (): void {
    CoseKey::fromDecoded([1 => 1, 3 => -8, -1 => 1, -2 => str_repeat("\x01", 32)]);
})->throws(UnsupportedAlgorithmException::class);

it('rejects an RSA key that is not RS256', function (): void {
    CoseKey::fromDecoded([1 => 3, 3 => -7, -1 => str_repeat("\x01", 32), -2 => "\x01\x00\x01"]);
})->throws(UnsupportedAlgorithmException::class);

it('rejects a missing integer label', function (): void {
    CoseKey::fromDecoded([3 => -7]);
})->throws(MalformedCborException::class);

it('rejects a missing binary field', function (): void {
    CoseKey::fromDecoded([1 => 2, 3 => -7, -1 => 1, -2 => str_repeat("\x01", 32)]);
})->throws(MalformedCborException::class);
