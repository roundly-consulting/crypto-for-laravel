<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Cose\CborDecoder;
use RoundlyConsulting\Crypto\CryptoManager;
use RoundlyConsulting\Crypto\Facades\Crypto;
use RoundlyConsulting\Crypto\Hash\HashAlgorithm;
use RoundlyConsulting\Crypto\Jose\Jws;
use RoundlyConsulting\Crypto\Otp\OtpAlgorithm;
use RoundlyConsulting\Crypto\Signature\KeyVerifier;

it('registers the key-less stateless services as singletons', function (): void {
    expect(app(Jws::class))->toBeInstanceOf(Jws::class)
        ->and(app(Jws::class))->toBe(app(Jws::class))
        ->and(app(CborDecoder::class))->toBe(app(CborDecoder::class))
        ->and(app(KeyVerifier::class))->toBe(app(KeyVerifier::class))
        ->and(app(CryptoManager::class))->toBe(app(CryptoManager::class));
});

it('resolves factory helpers through the Crypto facade', function (): void {
    expect(Crypto::jws())->toBeInstanceOf(Jws::class)
        ->and(strlen(Crypto::hmac(HashAlgorithm::Sha256)->sign('m', 'k')))->toBe(32)
        ->and(Crypto::digest()->hex('x'))->toBeString()
        ->and(Crypto::verifier())->toBeInstanceOf(KeyVerifier::class)
        ->and(Crypto::cbor())->toBeInstanceOf(CborDecoder::class)
        ->and(Crypto::totp(OtpAlgorithm::Sha1, 8, 60)->codeAt('JBSWY3DPEHPK3PXP', 0))->toHaveLength(8)
        ->and(Crypto::hotp(OtpAlgorithm::Sha1, 6)->at('JBSWY3DPEHPK3PXP', 0))->toHaveLength(6);
});

it('reports its status through the about command', function (): void {
    $this->artisan('about')->assertOk();
});
