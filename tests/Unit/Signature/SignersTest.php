<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Signature\Algorithm;
use RoundlyConsulting\Crypto\Signature\AlgorithmMismatchException;
use RoundlyConsulting\Crypto\Signature\EdDSA;
use RoundlyConsulting\Crypto\Signature\Es;
use RoundlyConsulting\Crypto\Signature\Hs;
use RoundlyConsulting\Crypto\Signature\Key\EcKey;
use RoundlyConsulting\Crypto\Signature\Key\HmacSecret;
use RoundlyConsulting\Crypto\Signature\Key\OkpKey;
use RoundlyConsulting\Crypto\Signature\Key\RsaKey;
use RoundlyConsulting\Crypto\Signature\KeyLoadException;
use RoundlyConsulting\Crypto\Signature\Rs;

function strongSecret(): HmacSecret
{
    return HmacSecret::fromString('0123456789abcdef0123456789abcdef!');
}

describe('Hs', function (): void {
    it('signs and verifies HS256', function (): void {
        $hs = new Hs(strongSecret());
        $sig = $hs->sign('message');

        expect($hs->algorithm())->toBe(Algorithm::HS256)
            ->and($hs->verify('message', $sig))->toBeTrue()
            ->and($hs->verify('tampered', $sig))->toBeFalse();
    });

    it('rejects construction for a non-HS algorithm', function (): void {
        new Hs(strongSecret(), Algorithm::RS256);
    })->throws(AlgorithmMismatchException::class);
});

describe('Rs', function (): void {
    it('signs with a private key and verifies with the public key', function (): void {
        $signer = new Rs(RsaKey::private(keyPem('rsa-private')));
        $verifier = new Rs(RsaKey::public(keyPem('rsa-public')));
        $sig = $signer->sign('message');

        expect($signer->algorithm())->toBe(Algorithm::RS256)
            ->and($verifier->verify('message', $sig))->toBeTrue()
            ->and($verifier->verify('tampered', $sig))->toBeFalse();
    });

    it('refuses to sign with a public-only key', function (): void {
        (new Rs(RsaKey::public(keyPem('rsa-public'))))->sign('message');
    })->throws(KeyLoadException::class);

    it('returns false for a garbage signature without warning', function (): void {
        expect((new Rs(RsaKey::public(keyPem('rsa-public'))))->verify('message', 'garbage'))->toBeFalse();
    });
});

describe('Es', function (): void {
    it('signs (raw r||s) and verifies ES256', function (): void {
        $signer = new Es(EcKey::private(keyPem('ec-private')));
        $verifier = new Es(EcKey::public(keyPem('ec-public')));
        $sig = $signer->sign('message');

        expect($signer->algorithm())->toBe(Algorithm::ES256)
            ->and(strlen($sig))->toBe(64)
            ->and($verifier->verify('message', $sig))->toBeTrue()
            ->and($verifier->verify('tampered', $sig))->toBeFalse();
    });

    it('verifies the committed ES256 vector', function (): void {
        $es256 = cryptoVectors()['es256'];
        $verifier = new Es(EcKey::public($es256['public_pem']));

        expect($verifier->verify(hex2bin($es256['message']), hex2bin($es256['sig_raw'])))->toBeTrue();
    });

    it('refuses to sign with a public-only key', function (): void {
        (new Es(EcKey::public(keyPem('ec-public'))))->sign('message');
    })->throws(KeyLoadException::class);

    it('rejects a signature of the wrong length', function (): void {
        expect((new Es(EcKey::public(keyPem('ec-public'))))->verify('message', 'short'))->toBeFalse();
    });
});

describe('EdDSA', function (): void {
    it('verifies the committed Ed25519 vector', function (): void {
        $eddsa = cryptoVectors()['eddsa'];
        $verifier = new EdDSA(OkpKey::ed25519(hex2bin($eddsa['public_raw'])));

        expect($verifier->algorithm())->toBe(Algorithm::EdDSA)
            ->and($verifier->verify(hex2bin($eddsa['message']), hex2bin($eddsa['sig'])))->toBeTrue();
    });

    it('rejects a tampered Ed25519 signature and signed data', function (): void {
        $eddsa = cryptoVectors()['eddsa'];
        $verifier = new EdDSA(OkpKey::ed25519(hex2bin($eddsa['public_raw'])));
        $sig = hex2bin($eddsa['sig']);
        $sig[0] = $sig[0] === "\x00" ? "\x01" : "\x00";

        expect($verifier->verify(hex2bin($eddsa['message']), $sig))->toBeFalse()
            ->and($verifier->verify('different data', hex2bin($eddsa['sig'])))->toBeFalse();
    });

    it('rejects a wrong-length Ed25519 signature', function (): void {
        $eddsa = cryptoVectors()['eddsa'];
        $verifier = new EdDSA(OkpKey::ed25519(hex2bin($eddsa['public_raw'])));

        expect($verifier->verify(hex2bin($eddsa['message']), 'short'))->toBeFalse();
    });
})->skip(fn (): bool => ! function_exists('sodium_crypto_sign_verify_detached'), 'ext-sodium not loaded');
