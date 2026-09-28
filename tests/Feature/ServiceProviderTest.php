<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Asn1\DerDecoder;
use RoundlyConsulting\Crypto\Cose\AuthenticatorData;
use RoundlyConsulting\Crypto\Cose\CborDecoder;
use RoundlyConsulting\Crypto\CryptoManager;
use RoundlyConsulting\Crypto\Facades\Crypto;
use RoundlyConsulting\Crypto\Hash\HashAlgorithm;
use RoundlyConsulting\Crypto\Jose\Jws;
use RoundlyConsulting\Crypto\Otp\OtpAlgorithm;
use RoundlyConsulting\Crypto\Signature\Algorithm;
use RoundlyConsulting\Crypto\Signature\EdDSA;
use RoundlyConsulting\Crypto\Signature\Es;
use RoundlyConsulting\Crypto\Signature\Hs;
use RoundlyConsulting\Crypto\Signature\Key\EcKey;
use RoundlyConsulting\Crypto\Signature\Key\HmacSecret;
use RoundlyConsulting\Crypto\Signature\Key\OkpKey;
use RoundlyConsulting\Crypto\Signature\Key\RsaKey;
use RoundlyConsulting\Crypto\Signature\KeyVerifier;
use RoundlyConsulting\Crypto\Signature\Rs;

it('registers the key-less stateless services as singletons', function (): void {
    expect(app(Jws::class))->toBeInstanceOf(Jws::class)
        ->and(app(Jws::class))->toBe(app(Jws::class))
        ->and(app(CborDecoder::class))->toBe(app(CborDecoder::class))
        ->and(app(DerDecoder::class))->toBe(app(DerDecoder::class))
        ->and(app(KeyVerifier::class))->toBe(app(KeyVerifier::class))
        ->and(app(CryptoManager::class))->toBe(app(CryptoManager::class));
});

it('resolves factory helpers through the Crypto facade', function (): void {
    expect(Crypto::jws())->toBeInstanceOf(Jws::class)
        ->and(strlen(Crypto::hmac(HashAlgorithm::Sha256)->sign('m', 'k')))->toBe(32)
        ->and(Crypto::digest()->hex('x'))->toBeString()
        ->and(Crypto::verifier())->toBeInstanceOf(KeyVerifier::class)
        ->and(Crypto::cbor())->toBeInstanceOf(CborDecoder::class)
        ->and(Crypto::derDecoder())->toBeInstanceOf(DerDecoder::class)
        ->and(Crypto::derDecoder()->decode("\x04\x02hi")->octetString())->toBe('hi')
        ->and(Crypto::totp(OtpAlgorithm::Sha1, 8, 60)->codeAt('JBSWY3DPEHPK3PXP', 0))->toHaveLength(8)
        ->and(Crypto::hotp(OtpAlgorithm::Sha1, 6)->at('JBSWY3DPEHPK3PXP', 0))->toHaveLength(6);
});

it('generates an HMAC secret through the facade without holding it', function (): void {
    $secret = Crypto::generateHmacSecret(48);

    expect($secret)->toBeInstanceOf(HmacSecret::class)
        ->and(strlen($secret->value))->toBe(48)
        ->and(Crypto::generateHmacSecret()->value)->not->toBe($secret->value);
});

it('surfaces the keyed signers through the facade', function (): void {
    $hs = Crypto::hs(HmacSecret::fromString(str_repeat('0123456789abcdef', 3)), Algorithm::HS384);
    $rs = Crypto::rs(RsaKey::public(keyPem('rsa-public')), Algorithm::RS512);
    $es = Crypto::es(EcKey::public(keyPem('ec-public')));
    $eddsa = Crypto::eddsa(OkpKey::ed25519(str_repeat("\x01", 32)));

    expect($hs)->toBeInstanceOf(Hs::class)
        ->and($hs->algorithm())->toBe(Algorithm::HS384)
        ->and($rs)->toBeInstanceOf(Rs::class)
        ->and($rs->algorithm())->toBe(Algorithm::RS512)
        ->and($es)->toBeInstanceOf(Es::class)
        ->and($eddsa)->toBeInstanceOf(EdDSA::class);
});

it('surfaces codecs, CSPRNG, and hashing through the facade', function (): void {
    expect(Crypto::base64UrlDecode(Crypto::base64UrlEncode('hi')))->toBe('hi')
        ->and(Crypto::base64Decode(Crypto::base64Encode('hi')))->toBe('hi')
        ->and(Crypto::base32Decode(Crypto::base32Encode('hi')))->toBe('hi')
        ->and(Crypto::hexDecode(Crypto::hexEncode('hi')))->toBe('hi')
        ->and(strlen(Crypto::randomBytes(16)))->toBe(16)
        ->and(Crypto::randomToken(40))->toHaveLength(40)
        ->and(Crypto::randomSecret(32))->toHaveLength(32)
        ->and(Crypto::constantTimeEquals('a', 'a'))->toBeTrue()
        ->and(Crypto::constantTimeEquals('a', 'b'))->toBeFalse();
});

it('surfaces COSE and OTP discovery helpers through the facade', function (): void {
    $es256 = cryptoVectors()['es256'];
    $key = Crypto::coseKey(hex2bin($es256['cose']));
    $authData = Crypto::authenticatorData(hex2bin(cryptoVectors()['auth_data']['bytes']));
    $uri = Crypto::provisioningUri('JBSWY3DPEHPK3PXP', 'alice', 'Acme');

    expect($key->algorithm())->toBe(Algorithm::ES256)
        ->and($authData)->toBeInstanceOf(AuthenticatorData::class)
        ->and($uri)->toStartWith('otpauth://totp/Acme:alice?');
});

it('reports its status through the about command', function (): void {
    $this->artisan('about --only=crypto')
        ->assertOk()
        ->expectsOutputToContain('JOSE / JWS');
});

it('reveals the JWK and X.509 entry points through the facade', function (): void {
    $fixture = RoundlyConsulting\Crypto\Testing\TestCertificates::chain();
    $key = EcKey::generate();
    $jwk = Crypto::jwk($key);

    expect($jwk)->toBeInstanceOf(RoundlyConsulting\Crypto\Jose\Jwk::class)
        ->and(Crypto::jwkFromArray($jwk->toArray())->thumbprint())->toBe($jwk->thumbprint())
        ->and(Crypto::jwkFromJson((string) json_encode($jwk))->thumbprint())->toBe($jwk->thumbprint())
        ->and(Crypto::certificate($fixture->leaf()->pem())->der())->toBe($fixture->leaf()->der())
        ->and(Crypto::chainFromX5c($fixture->x5c())->count())->toBe(3)
        ->and(Crypto::chainFromX5c($fixture->x5c())->isLinked())->toBeTrue()
        ->and(Crypto::chainFromPemBundle($fixture->pemBundle())->fingerprints())
        ->toBe($fixture->chain->fingerprints());
});
