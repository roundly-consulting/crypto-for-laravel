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
    it('signs and verifies each HMAC tier', function (Algorithm $algorithm, int $length): void {
        $hs = new Hs(strongSecret(), $algorithm);
        $sig = $hs->sign('message');

        expect($hs->algorithm())->toBe($algorithm)
            ->and(strlen($sig))->toBe($length)
            ->and($hs->verify('message', $sig))->toBeTrue()
            ->and($hs->verify('tampered', $sig))->toBeFalse();
    })->with([
        'HS256' => [Algorithm::HS256, 32],
        'HS384' => [Algorithm::HS384, 48],
        'HS512' => [Algorithm::HS512, 64],
    ]);

    it('rejects construction for a non-HS algorithm', function (Algorithm $algorithm): void {
        new Hs(strongSecret(), $algorithm);
    })->with([
        'RS256' => [Algorithm::RS256],
        'ES256' => [Algorithm::ES256],
        'EdDSA' => [Algorithm::EdDSA],
    ])->throws(AlgorithmMismatchException::class);
});

describe('Rs', function (): void {
    it('signs and verifies each RSA tier', function (Algorithm $algorithm): void {
        $signer = new Rs(RsaKey::private(keyPem('rsa-private')), $algorithm);
        $verifier = new Rs(RsaKey::public(keyPem('rsa-public')), $algorithm);
        $sig = $signer->sign('message');

        expect($signer->algorithm())->toBe($algorithm)
            ->and($verifier->verify('message', $sig))->toBeTrue()
            ->and($verifier->verify('tampered', $sig))->toBeFalse();
    })->with([
        'RS256' => [Algorithm::RS256],
        'RS384' => [Algorithm::RS384],
        'RS512' => [Algorithm::RS512],
    ]);

    it('does not cross-verify across RSA tiers', function (): void {
        $sig = (new Rs(RsaKey::private(keyPem('rsa-private')), Algorithm::RS512))->sign('message');

        expect((new Rs(RsaKey::public(keyPem('rsa-public')), Algorithm::RS256))->verify('message', $sig))->toBeFalse();
    });

    it('rejects construction for a non-RSA algorithm', function (): void {
        new Rs(RsaKey::public(keyPem('rsa-public')), Algorithm::ES256);
    })->throws(AlgorithmMismatchException::class);

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

    it('signs and verifies ES384 and ES512 round-trips on a generated key', function (string $curve, Algorithm $algorithm, int $length): void {
        $key = EcKey::generate($curve);
        $public = EcKey::public((string) openssl_pkey_get_details($key->key)['key']);
        $sig = (new Es($key))->sign('message');

        expect((new Es($key))->algorithm())->toBe($algorithm)
            ->and(strlen($sig))->toBe($length)
            ->and((new Es($public))->verify('message', $sig))->toBeTrue()
            ->and((new Es($public))->verify('tampered', $sig))->toBeFalse();
    })->with([
        'ES384' => ['P-384', Algorithm::ES384, 96],
        'ES512' => ['P-521', Algorithm::ES512, 132],
    ]);

    it('verifies each committed ES vector', function (string $name): void {
        $vector = cryptoVectors()[$name];
        $verifier = new Es(EcKey::public($vector['public_pem']));

        expect($verifier->verify(hex2bin($vector['message']), hex2bin($vector['sig_raw'])))->toBeTrue()
            ->and($verifier->verify('tampered', hex2bin($vector['sig_raw'])))->toBeFalse();
    })->with(['es256', 'es384', 'es512']);

    it('accepts both a signature and its malleable r||(n-s) twin (raw ECDSA is malleable)', function (): void {
        // Property: raw ECDSA is malleable — s and n−s are both valid. The two
        // are DISTINCT byte strings, so a caller must never treat a signature as a
        // unique idempotency/dedup key. This pins the behaviour, it does not fix
        // it (JOSE/WebAuthn do not require low-S).
        $vector = cryptoVectors()['es256'];
        $verifier = new Es(EcKey::public($vector['public_pem']));

        expect($vector['sig_raw'])->not->toBe($vector['sig_raw_high_s'])
            ->and($verifier->verify(hex2bin($vector['message']), hex2bin($vector['sig_raw'])))->toBeTrue()
            ->and($verifier->verify(hex2bin($vector['message']), hex2bin($vector['sig_raw_high_s'])))->toBeTrue();
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

    it('rejects a small-order (all-zero) Ed25519 public key at verify', function (): void {
        // Property: libsodium rejects small-order points, so an all-zero public
        // key can never make a signature verify. verify() returns false rather
        // than throwing or accepting.
        $verifier = new EdDSA(OkpKey::ed25519(str_repeat("\x00", 32)));

        expect($verifier->verify('message', str_repeat("\x00", 64)))->toBeFalse()
            ->and($verifier->verify(hex2bin(cryptoVectors()['eddsa']['message']), hex2bin(cryptoVectors()['eddsa']['sig'])))->toBeFalse();
    });

    it('rejects a wrong-length Ed25519 signature', function (): void {
        $eddsa = cryptoVectors()['eddsa'];
        $verifier = new EdDSA(OkpKey::ed25519(hex2bin($eddsa['public_raw'])));

        expect($verifier->verify(hex2bin($eddsa['message']), 'short'))->toBeFalse();
    });

    it('signs and verifies with a generated Ed25519 key', function (): void {
        $key = OkpKey::generate();
        $eddsa = new EdDSA($key);
        $sig = $eddsa->sign('message');

        expect($eddsa->algorithm())->toBe(Algorithm::EdDSA)
            ->and(strlen($sig))->toBe(64)
            ->and($eddsa->verify('message', $sig))->toBeTrue()
            ->and($eddsa->verify('tampered', $sig))->toBeFalse();
    });

    it('reproduces the RFC 8032 section 7.1 Ed25519 known-answer vector', function (): void {
        // RFC 8032 TEST 2: seed + public form the 64-byte libsodium secret key.
        $seed = hex2bin('4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb');
        $public = hex2bin('3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c');
        $key = OkpKey::fromSecretKey($seed.$public);
        $signature = (new EdDSA($key))->sign((string) hex2bin('72'));

        expect(bin2hex($signature))
            ->toBe('92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00')
            ->and((new EdDSA(OkpKey::ed25519((string) $public)))->verify((string) hex2bin('72'), $signature))->toBeTrue();
    });

    it('signs with a key restored from its secret key', function (): void {
        $generated = OkpKey::generate();
        $restored = OkpKey::fromSecretKey((string) $generated->secretKey);
        $sig = (new EdDSA($restored))->sign('message');

        expect($restored->publicKey)->toBe($generated->publicKey)
            ->and((new EdDSA(OkpKey::ed25519($generated->publicKey)))->verify('message', $sig))->toBeTrue();
    });

    it('refuses to sign with a public-only key', function (): void {
        $eddsa = cryptoVectors()['eddsa'];
        (new EdDSA(OkpKey::ed25519(hex2bin($eddsa['public_raw']))))->sign('message');
    })->throws(KeyLoadException::class);

    it('rejects a secret key of the wrong length', function (): void {
        OkpKey::fromSecretKey('short');
    })->throws(KeyLoadException::class);
})->skip(fn (): bool => ! function_exists('sodium_crypto_sign_verify_detached'), 'ext-sodium not loaded');
