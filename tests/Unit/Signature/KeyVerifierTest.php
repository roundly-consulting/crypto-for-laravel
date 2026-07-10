<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Cose\CoseKey;
use RoundlyConsulting\Crypto\Signature\Ec\Der;
use RoundlyConsulting\Crypto\Signature\Key\EcKey;
use RoundlyConsulting\Crypto\Signature\KeyVerifier;

it('verifies an ES256 signature in DER form (WebAuthn)', function (): void {
    $es256 = cryptoVectors()['es256'];
    $key = CoseKey::fromDecoded((new RoundlyConsulting\Crypto\Cose\CborDecoder)->decode(hex2bin($es256['cose'])));

    expect((new KeyVerifier)->verify($key, hex2bin($es256['message']), hex2bin($es256['sig_der'])))->toBeTrue();
});

it('verifies an ES256 signature in raw r||s form', function (): void {
    $es256 = cryptoVectors()['es256'];
    $key = CoseKey::fromDecoded((new RoundlyConsulting\Crypto\Cose\CborDecoder)->decode(hex2bin($es256['cose'])));

    expect((new KeyVerifier)->verify($key, hex2bin($es256['message']), hex2bin($es256['sig_raw'])))->toBeTrue();
});

it('verifies an RS256 signature', function (): void {
    $rs256 = cryptoVectors()['rs256'];
    $key = CoseKey::fromDecoded((new RoundlyConsulting\Crypto\Cose\CborDecoder)->decode(hex2bin($rs256['cose'])));

    expect((new KeyVerifier)->verify($key, hex2bin($rs256['message']), hex2bin($rs256['sig'])))->toBeTrue();
});

it('rejects a malformed ES256 signature', function (): void {
    $es256 = cryptoVectors()['es256'];
    $key = CoseKey::fromDecoded((new RoundlyConsulting\Crypto\Cose\CborDecoder)->decode(hex2bin($es256['cose'])));

    expect((new KeyVerifier)->verify($key, hex2bin($es256['message']), 'neither-der-nor-raw'))->toBeFalse();
});

it('rejects a tampered ES256 message', function (): void {
    $es256 = cryptoVectors()['es256'];
    $key = CoseKey::fromDecoded((new RoundlyConsulting\Crypto\Cose\CborDecoder)->decode(hex2bin($es256['cose'])));

    expect((new KeyVerifier)->verify($key, 'tampered', hex2bin($es256['sig_der'])))->toBeFalse();
});

it('rejects an ES256 DER signature whose integers are out of range', function (): void {
    $es256 = cryptoVectors()['es256'];
    $key = CoseKey::fromDecoded((new RoundlyConsulting\Crypto\Cose\CborDecoder)->decode(hex2bin($es256['cose'])));

    // Structurally-valid DER with 64-byte integers cannot be a P-256 signature.
    $oversized = Der::fromRaw(str_repeat("\x7f", 128), 64);

    expect((new KeyVerifier)->verify($key, hex2bin($es256['message']), $oversized))->toBeFalse();
});

it('verifies ES384/ES512 in both raw and DER form using the key coordinate size', function (string $name, int $coordinateBytes): void {
    $vector = cryptoVectors()[$name];
    $key = EcKey::public($vector['public_pem']);
    $raw = hex2bin($vector['sig_raw']);
    $der = Der::fromRaw($raw, $coordinateBytes);
    $verifier = new KeyVerifier;

    expect($verifier->verify($key, hex2bin($vector['message']), $raw))->toBeTrue()
        ->and($verifier->verify($key, hex2bin($vector['message']), $der))->toBeTrue()
        ->and($verifier->verify($key, 'tampered', $raw))->toBeFalse();
})->with([
    'ES384' => ['es384', 48],
    'ES512' => ['es512', 66],
]);

it('verifies an EdDSA signature', function (): void {
    $eddsa = cryptoVectors()['eddsa'];
    $key = CoseKey::fromDecoded((new RoundlyConsulting\Crypto\Cose\CborDecoder)->decode(hex2bin($eddsa['cose'])));

    expect((new KeyVerifier)->verify($key, hex2bin($eddsa['message']), hex2bin($eddsa['sig'])))->toBeTrue();
})->skip(fn (): bool => ! function_exists('sodium_crypto_sign_verify_detached'), 'ext-sodium not loaded');
