<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Signature\Key\EcKey;
use RoundlyConsulting\Crypto\Signature\KeyLoadException;
use RoundlyConsulting\Crypto\Signature\OpenSsl;

it('turns a key-generation failure into a typed exception', function (): void {
    // A bad `config` path makes openssl_pkey_new fail even where the default
    // openssl.cnf is healthy, so this covers the warning-free failure path on
    // every runner.
    OpenSsl::generateKey([
        'private_key_type' => OPENSSL_KEYTYPE_EC,
        'curve_name' => 'prime256v1',
        'config' => '/nonexistent/openssl.cnf',
    ]);
})->throws(KeyLoadException::class);

it('turns a signing failure into a typed exception', function (): void {
    // Signing with a public-only key makes openssl_sign fail.
    $public = EcKey::public(keyPem('ec-public'));

    OpenSsl::sign('message', $public->key, OPENSSL_ALGO_SHA256);
})->throws(KeyLoadException::class);

it('drains the error queue and returns false for a malformed signature', function (): void {
    $public = EcKey::public(keyPem('ec-public'));

    // A structurally-broken DER makes openssl_verify return -1 (an error), which
    // must be drained and reported as a plain false, not a warning.
    expect(OpenSsl::verify('message', str_repeat("\xff", 70), $public->key, OPENSSL_ALGO_SHA256))->toBeFalse()
        ->and(openssl_error_string())->toBeFalse();
});
