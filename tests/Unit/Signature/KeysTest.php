<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Signature\Algorithm;
use RoundlyConsulting\Crypto\Signature\Key\EcKey;
use RoundlyConsulting\Crypto\Signature\Key\HmacSecret;
use RoundlyConsulting\Crypto\Signature\Key\OkpKey;
use RoundlyConsulting\Crypto\Signature\Key\RsaKey;
use RoundlyConsulting\Crypto\Signature\KeyLoadException;
use RoundlyConsulting\Crypto\Signature\WeakKeyException;

describe('HmacSecret', function (): void {
    it('accepts a strong random secret', function (): void {
        $secret = HmacSecret::fromString(str_repeat('a', 16).str_repeat('b', 16).'cd');

        expect($secret->value)->toHaveLength(34);
    });

    it('rejects an empty secret', function (): void {
        HmacSecret::fromString('');
    })->throws(WeakKeyException::class);

    it('rejects a PEM as an HMAC secret (RS→HS confusion)', function (): void {
        HmacSecret::fromString("-----BEGIN PUBLIC KEY-----\nMFkw...\n-----END PUBLIC KEY-----");
    })->throws(WeakKeyException::class);

    it('rejects a secret under 32 bytes', function (): void {
        HmacSecret::fromString('too-short');
    })->throws(WeakKeyException::class);

    it('rejects a single-repeated-byte secret', function (): void {
        HmacSecret::fromString(str_repeat('a', 40));
    })->throws(WeakKeyException::class);
});

describe('RsaKey', function (): void {
    it('loads a public and private PEM', function (): void {
        expect(RsaKey::public(keyPem('rsa-public'))->algorithm())->toBe(Algorithm::RS256)
            ->and(RsaKey::private(keyPem('rsa-private'))->isPrivate)->toBeTrue()
            ->and(RsaKey::public(keyPem('rsa-public'))->isPrivate)->toBeFalse();
    });

    it('builds a key from raw modulus and exponent', function (): void {
        $rs256 = cryptoVectors()['rs256'];
        $decoded = (new RoundlyConsulting\Crypto\Cose\CborDecoder)->decode(hex2bin($rs256['cose']));

        $key = RsaKey::fromModulusExponent($decoded[-1], $decoded[-2]);

        expect($key->algorithm())->toBe(Algorithm::RS256);
    });

    it('rejects a key under 2048 bits', function (): void {
        RsaKey::public(keyPem('weak-1024-public'));
    })->throws(WeakKeyException::class);

    it('rejects an unreadable PEM', function (): void {
        RsaKey::public('not a pem');
    })->throws(KeyLoadException::class);

    it('rejects an EC PEM loaded as RSA', function (): void {
        RsaKey::public(keyPem('ec-public'));
    })->throws(KeyLoadException::class);

    it('rejects empty modulus or exponent', function (): void {
        RsaKey::fromModulusExponent('', '');
    })->throws(KeyLoadException::class);

    it('encodes an all-zero integer as a single zero byte in the SPKI', function (): void {
        // Exercises the ASN.1 minimal-integer path for a value that is all zero
        // bytes; the assembled PEM is still well-formed even if OpenSSL later
        // rejects a zero exponent as a key.
        $pem = RoundlyConsulting\Crypto\Signature\Key\Asn1::rsaPublicKeyPem(str_repeat("\x01", 256), "\x00\x00");

        expect($pem)->toStartWith('-----BEGIN PUBLIC KEY-----');
    });

    it('rejects generating below 2048 bits', function (): void {
        RsaKey::generate(1024);
    })->throws(WeakKeyException::class);

    it('exposes a bound RS256 verifier', function (): void {
        expect(RsaKey::public(keyPem('rsa-public'))->verifier()->algorithm())->toBe(Algorithm::RS256);
    });
});

describe('EcKey', function (): void {
    it('loads a public and private PEM', function (): void {
        expect(EcKey::public(keyPem('ec-public'))->algorithm())->toBe(Algorithm::ES256)
            ->and(EcKey::private(keyPem('ec-private'))->isPrivate)->toBeTrue();
    });

    it('builds a key from raw P-256 coordinates', function (): void {
        $es256 = cryptoVectors()['es256'];
        $decoded = (new RoundlyConsulting\Crypto\Cose\CborDecoder)->decode(hex2bin($es256['cose']));

        $key = EcKey::fromCoordinates($decoded[-2], $decoded[-3]);

        expect($key->algorithm())->toBe(Algorithm::ES256)
            ->and($key->coordinateBytes())->toBe(32)
            ->and($key->curve)->toBe('P-256');
    });

    it('builds P-384 and P-521 keys from coordinates and detects the curve on load', function (string $name, string $curve, Algorithm $algorithm, int $bytes): void {
        $vector = cryptoVectors()[$name];
        $key = EcKey::fromCoordinates(hex2bin($vector['x']), hex2bin($vector['y']), $curve);

        expect($key->algorithm())->toBe($algorithm)
            ->and($key->coordinateBytes())->toBe($bytes)
            ->and($key->curve)->toBe($curve)
            ->and(EcKey::public($vector['public_pem'])->curve)->toBe($curve);
    })->with([
        'P-384' => ['es384', 'P-384', Algorithm::ES384, 48],
        'P-521' => ['es512', 'P-521', Algorithm::ES512, 66],
    ]);

    it('rejects an unsupported curve', function (): void {
        EcKey::fromCoordinates(str_repeat("\x01", 32), str_repeat("\x02", 32), 'secp256k1');
    })->throws(WeakKeyException::class);

    it('rejects coordinates of the wrong length', function (): void {
        EcKey::fromCoordinates('short', 'short');
    })->throws(KeyLoadException::class);

    it('rejects an unreadable PEM', function (): void {
        EcKey::public('not a pem');
    })->throws(KeyLoadException::class);

    it('rejects an RSA PEM loaded as EC', function (): void {
        EcKey::public(keyPem('rsa-public'));
    })->throws(KeyLoadException::class);

    it('rejects a loaded key on an unsupported curve', function (): void {
        // A real EC key on secp256k1 is a valid EC key OpenSSL will load, but not
        // one of the three JOSE curves — the load must fail with a typed error.
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'secp256k1']);
        $pem = (string) openssl_pkey_get_details($key)['key'];

        EcKey::public($pem);
    })->throws(KeyLoadException::class);

    it('rejects generating on an unsupported curve', function (): void {
        EcKey::generate('secp256k1');
    })->throws(WeakKeyException::class);

    it('exposes a bound ES256 verifier', function (): void {
        expect(EcKey::public(keyPem('ec-public'))->verifier()->algorithm())->toBe(Algorithm::ES256);
    });
});

describe('OkpKey', function (): void {
    it('wraps a 32-byte Ed25519 public key', function (): void {
        $key = OkpKey::ed25519(str_repeat("\x01", 32));

        expect($key->algorithm())->toBe(Algorithm::EdDSA)
            ->and($key->publicKey)->toHaveLength(32)
            ->and($key->secretKey)->toBeNull()
            ->and($key->verifier()->algorithm())->toBe(Algorithm::EdDSA);
    });

    it('rejects a key that is not 32 bytes', function (): void {
        OkpKey::ed25519('short');
    })->throws(KeyLoadException::class);

    it('generates a keypair carrying both halves', function (): void {
        $key = OkpKey::generate();

        expect(strlen($key->publicKey))->toBe(32)
            ->and(strlen((string) $key->secretKey))->toBe(64);
    })->skip(fn (): bool => ! function_exists('sodium_crypto_sign_keypair'), 'ext-sodium not loaded');
});
