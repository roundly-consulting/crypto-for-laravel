<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Signature\Algorithm;
use RoundlyConsulting\Crypto\Signature\Es;
use RoundlyConsulting\Crypto\Signature\Key\EcKey;
use RoundlyConsulting\Crypto\Signature\Key\RsaKey;
use RoundlyConsulting\Crypto\Signature\KeyLoadException;
use RoundlyConsulting\Crypto\Signature\Rs;

it('generates a usable RSA private key', function (): void {
    $key = RsaKey::generate(2048);
    $public = RsaKey::public((string) openssl_pkey_get_details($key->key)['key']);
    $sig = (new Rs($key))->sign('message');

    expect($key->algorithm())->toBe(Algorithm::RS256)
        ->and($key->isPrivate)->toBeTrue()
        ->and((new Rs($public))->verify('message', $sig))->toBeTrue();
});

it('generates a usable EC private key', function (): void {
    $key = EcKey::generate();
    $public = EcKey::public((string) openssl_pkey_get_details($key->key)['key']);
    $sig = (new Es($key))->sign('message');

    expect($key->algorithm())->toBe(Algorithm::ES256)
        ->and($key->isPrivate)->toBeTrue()
        ->and(strlen($sig))->toBe(64)
        ->and((new Es($public))->verify('message', $sig))->toBeTrue();
});

it('rejects an unreadable RSA private PEM', function (): void {
    RsaKey::private('not a private key');
})->throws(KeyLoadException::class);

it('rejects an unreadable EC private PEM', function (): void {
    EcKey::private('not a private key');
})->throws(KeyLoadException::class);
