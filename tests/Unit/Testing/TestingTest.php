<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Jose\Jws;
use RoundlyConsulting\Crypto\Signature\Algorithm;
use RoundlyConsulting\Crypto\Signature\EdDSA;
use RoundlyConsulting\Crypto\Signature\Es;
use RoundlyConsulting\Crypto\Signature\Hs;
use RoundlyConsulting\Crypto\Signature\Key\EcKey;
use RoundlyConsulting\Crypto\Signature\Key\HmacSecret;
use RoundlyConsulting\Crypto\Signature\Key\OkpKey;
use RoundlyConsulting\Crypto\Signature\Key\RsaKey;
use RoundlyConsulting\Crypto\Signature\Rs;
use RoundlyConsulting\Crypto\Testing\TestKeys;
use RoundlyConsulting\Crypto\Testing\TestOtp;

describe('TestKeys', function (): void {
    it('mints a usable, valid HMAC secret', function (): void {
        $secret = TestKeys::hmacSecret();

        expect($secret)->toBeInstanceOf(HmacSecret::class);

        $signer = new Hs($secret);
        expect($signer->verify('m', $signer->sign('m')))->toBeTrue();
    });

    it('mints an ephemeral RSA signing key', function (): void {
        $key = TestKeys::rsa();
        $signer = new Rs($key);

        expect($key)->toBeInstanceOf(RsaKey::class)
            ->and((new Rs(RsaKey::public((string) openssl_pkey_get_details($key->key)['key'])))->verify('m', $signer->sign('m')))->toBeTrue();
    });

    it('mints an ephemeral EC signing key', function (): void {
        $key = TestKeys::ec();
        $signer = new Es($key);

        expect($key)->toBeInstanceOf(EcKey::class)
            ->and((new Es(EcKey::public((string) openssl_pkey_get_details($key->key)['key'])))->verify('m', $signer->sign('m')))->toBeTrue();
    });

    it('reports Ed25519 support and mints an Ed25519 key when available', function (): void {
        expect(TestKeys::supportsEd25519())->toBe(function_exists('sodium_crypto_sign_keypair'));

        if (! TestKeys::supportsEd25519()) {
            return;
        }

        $key = TestKeys::ed25519();
        $signer = new EdDSA($key);

        expect($key)->toBeInstanceOf(OkpKey::class)
            ->and($signer->verify('m', $signer->sign('m')))->toBeTrue();
    });
});

describe('TestOtp', function (): void {
    it('produces a code that verifies against the known secret', function (): void {
        $timestamp = 1_700_000_000;
        $code = TestOtp::codeAt($timestamp);

        expect($code)->toHaveLength(6)
            ->and(TestOtp::SECRET)->toBe('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');

        // The code verifies at its own timestep with the default parameters.
        expect($code)->toBeValidTotp(TestOtp::SECRET, $timestamp);
    });
});

describe('opt-in Pest expectations', function (): void {
    it('passes a valid JWS through toBeValidJws', function (): void {
        $secret = TestKeys::hmacSecret();
        $compact = (new Jws)->sign([], ['sub' => 'x'], new Hs($secret));

        expect($compact)->toBeValidJws(new Hs($secret), Algorithm::HS256);
    });

    it('fails toBeValidJws for a tampered token', function (): void {
        $secret = TestKeys::hmacSecret();
        $compact = (new Jws)->sign([], ['sub' => 'x'], new Hs($secret));

        expect(fn (): mixed => expect(substr($compact, 0, -4).'AAAA')->toBeValidJws(new Hs($secret), Algorithm::HS256))
            ->toThrow(RoundlyConsulting\Crypto\Signature\InvalidSignatureException::class);
    });
});
