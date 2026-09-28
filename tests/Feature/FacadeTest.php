<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Storage;
use RoundlyConsulting\Crypto\CryptoManager;
use RoundlyConsulting\Crypto\Facades\Crypto;
use RoundlyConsulting\Crypto\Random\Csprng;
use RoundlyConsulting\Crypto\Random\InvalidLengthException;
use RoundlyConsulting\Crypto\Signature\Algorithm;
use RoundlyConsulting\Crypto\Signature\Ec\Der;
use RoundlyConsulting\Crypto\Signature\Ec\DerCodec;
use RoundlyConsulting\Crypto\Signature\InvalidSignatureException;
use RoundlyConsulting\Crypto\Signature\Key\EcKey;
use RoundlyConsulting\Crypto\Signature\Key\HmacSecret;
use RoundlyConsulting\Crypto\Signature\Key\Keys;
use RoundlyConsulting\Crypto\Signature\Key\OkpKey;
use RoundlyConsulting\Crypto\Signature\Key\RsaKey;
use RoundlyConsulting\Crypto\Signature\KeyLoadException;
use RoundlyConsulting\Crypto\Signature\WeakKeyException;
use RoundlyConsulting\Crypto\Testing\TestCertificates;
use RoundlyConsulting\Crypto\X509\Certificate;
use RoundlyConsulting\Crypto\X509\Certificates;
use RoundlyConsulting\Crypto\X509\Chain;
use RoundlyConsulting\Crypto\X509\InvalidChainException;
use RoundlyConsulting\Crypto\X509\MalformedCertificateException;

beforeEach(function (): void {
    Storage::fake('keys');
});

it('documents its root', function (): void {
    // No `toReachEveryAction()`: crypto has no `src/Actions` — it is stateless computation,
    // which the convention lets expose service objects instead of actions.
    // No `toBeFakeable()`: nothing to intercept (no database, queue, event, mail or HTTP);
    // the key loaders' only I/O is Laravel's `Storage`, which `Storage::fake()` covers.
    expect(Crypto::class)->toDocumentItsRoot();
});

it('serves the same API to an injected manager', function (): void {
    $bytes = app()->call(static fn (CryptoManager $crypto): string => $crypto->random()->bytes(16));
    $secret = app(CryptoManager::class)->keys()->hmac()->generate();

    expect(Crypto::getFacadeRoot())->toBe(app(CryptoManager::class))
        ->and(strlen($bytes))->toBe(16)
        ->and(strlen($secret->value))->toBe(32);
});

it('hands out the four sub-accessors', function (): void {
    expect(Crypto::keys())->toBeInstanceOf(Keys::class)
        ->and(Crypto::random())->toBeInstanceOf(Csprng::class)
        ->and(Crypto::x509())->toBeInstanceOf(Certificates::class)
        ->and(Crypto::ecDer())->toBeInstanceOf(DerCodec::class);
});

describe('Crypto::keys()->rsa()', function (): void {
    it('loads PEMs exactly as RsaKey does', function (): void {
        $public = Crypto::keys()->rsa()->public(keyPem('rsa-public'));
        $private = Crypto::keys()->rsa()->private(keyPem('rsa-private'));

        expect($public)->toBeInstanceOf(RsaKey::class)
            ->and($public->isPrivate)->toBeFalse()
            ->and($public->publicPem())->toBe(RsaKey::public(keyPem('rsa-public'))->publicPem())
            ->and($private->isPrivate)->toBeTrue()
            ->and($private->publicPem())->toBe($public->publicPem());
    });

    it('rebuilds a public key from its modulus and exponent', function (): void {
        $public = RsaKey::public(keyPem('rsa-public'));

        $rebuilt = Crypto::keys()->rsa()->fromModulusExponent($public->modulus(), $public->exponent());

        expect($rebuilt->publicPem())->toBe($public->publicPem());
    });

    it('generates a key and keeps the size guard', function (): void {
        $key = Crypto::keys()->rsa()->generate(2048);

        expect($key->isPrivate)->toBeTrue()
            ->and(openssl_pkey_get_details($key->key)['bits'] ?? null)->toBe(2048);

        Crypto::keys()->rsa()->generate(1024);
    })->throws(WeakKeyException::class);

    it('loads from a disk and from your config', function (): void {
        Storage::disk('keys')->put('rsa.pub', keyPem('rsa-public'));
        Storage::disk('keys')->put('rsa.pem', keyPem('rsa-private'));
        config(['tokens.rsa.public' => keyPem('rsa-public'), 'tokens.rsa.private' => keyPem('rsa-private')]);

        $expected = RsaKey::public(keyPem('rsa-public'))->publicPem();

        expect(Crypto::keys()->rsa()->publicFromStorage('keys', 'rsa.pub')->publicPem())->toBe($expected)
            ->and(Crypto::keys()->rsa()->privateFromStorage('keys', 'rsa.pem')->isPrivate)->toBeTrue()
            ->and(Crypto::keys()->rsa()->publicFromConfig('tokens.rsa.public')->publicPem())->toBe($expected)
            ->and(Crypto::keys()->rsa()->privateFromConfig('tokens.rsa.private')->publicPem())->toBe($expected);
    });

    it('generates on first boot and reloads the same key after', function (): void {
        $first = Crypto::keys()->rsa()->fromStorageOrGenerate('keys', 'rsa.pem', 2048);
        $again = Crypto::keys()->rsa()->fromStorageOrGenerate('keys', 'rsa.pem', 2048);

        expect(Storage::disk('keys')->get('rsa.pem'))->toBe($first->privatePem())
            ->and($again->publicPem())->toBe($first->publicPem());
    });

    it('fails with the key class\'s typed error', function (): void {
        Crypto::keys()->rsa()->public('not a pem');
    })->throws(KeyLoadException::class);
});

describe('Crypto::keys()->ec()', function (): void {
    it('loads PEMs exactly as EcKey does', function (): void {
        $public = Crypto::keys()->ec()->public(keyPem('ec-public'));
        $private = Crypto::keys()->ec()->private(keyPem('ec-private'));

        expect($public)->toBeInstanceOf(EcKey::class)
            ->and($public->isPrivate)->toBeFalse()
            ->and($public->publicPem())->toBe(EcKey::public(keyPem('ec-public'))->publicPem())
            ->and($private->isPrivate)->toBeTrue()
            ->and($private->publicPem())->toBe($public->publicPem());
    });

    it('rebuilds a public key from its coordinates', function (): void {
        $public = EcKey::public(keyPem('ec-public'));
        $point = $public->coordinates();

        expect(Crypto::keys()->ec()->fromCoordinates($point->x, $point->y)->publicPem())->toBe($public->publicPem())
            ->and(Crypto::keys()->ec()->fromCoordinates($point->x, $point->y, 'P-256')->curve)->toBe('P-256');
    });

    it('generates on the requested curve and keeps the curve guard', function (): void {
        expect(Crypto::keys()->ec()->generate()->algorithm())->toBe(Algorithm::ES256)
            ->and(Crypto::keys()->ec()->generate('P-384')->algorithm())->toBe(Algorithm::ES384);

        Crypto::keys()->ec()->generate('P-192');
    })->throws(WeakKeyException::class);

    it('loads from a disk and from your config', function (): void {
        Storage::disk('keys')->put('ec.pub', keyPem('ec-public'));
        Storage::disk('keys')->put('ec.pem', keyPem('ec-private'));
        config(['tokens.ec.public' => keyPem('ec-public'), 'tokens.ec.private' => keyPem('ec-private')]);

        $expected = EcKey::public(keyPem('ec-public'))->publicPem();

        expect(Crypto::keys()->ec()->publicFromStorage('keys', 'ec.pub')->publicPem())->toBe($expected)
            ->and(Crypto::keys()->ec()->privateFromStorage('keys', 'ec.pem')->isPrivate)->toBeTrue()
            ->and(Crypto::keys()->ec()->publicFromConfig('tokens.ec.public')->publicPem())->toBe($expected)
            ->and(Crypto::keys()->ec()->privateFromConfig('tokens.ec.private')->publicPem())->toBe($expected);
    });

    it('generates on first boot and reloads the same key after', function (): void {
        $first = Crypto::keys()->ec()->fromStorageOrGenerate('keys', 'ec.pem', 'P-384');
        $again = Crypto::keys()->ec()->fromStorageOrGenerate('keys', 'ec.pem');

        expect(Storage::disk('keys')->get('ec.pem'))->toBe($first->privatePem())
            ->and($again->curve)->toBe('P-384')
            ->and($again->publicPem())->toBe($first->publicPem());
    });
});

describe('Crypto::keys()->ed25519()', function (): void {
    it('loads a raw public key without ext-sodium', function (): void {
        $key = Crypto::keys()->ed25519()->public(str_repeat("\x01", 32));

        expect($key)->toBeInstanceOf(OkpKey::class)
            ->and($key->secretKey)->toBeNull()
            ->and($key->algorithm())->toBe(Algorithm::EdDSA);

        Crypto::keys()->ed25519()->public('short');
    })->throws(KeyLoadException::class);

    it('generates and reloads a signing key', function (): void {
        $key = Crypto::keys()->ed25519()->generate();
        $reloaded = Crypto::keys()->ed25519()->private((string) $key->secretKey);

        expect($reloaded->publicKey)->toBe($key->publicKey)
            ->and($reloaded->secretKey)->toBe($key->secretKey);
    })->skip(fn (): bool => ! function_exists('sodium_crypto_sign_keypair'), 'ext-sodium not loaded');

    it('loads from a disk and from your config', function (): void {
        $key = OkpKey::generate();
        Storage::disk('keys')->put('ed.pub', $key->publicKey);
        Storage::disk('keys')->put('ed.key', (string) $key->secretKey);
        config(['tokens.ed.public' => $key->publicKey, 'tokens.ed.secret' => $key->secretKey]);

        expect(Crypto::keys()->ed25519()->publicFromStorage('keys', 'ed.pub')->publicKey)->toBe($key->publicKey)
            ->and(Crypto::keys()->ed25519()->privateFromStorage('keys', 'ed.key')->publicKey)->toBe($key->publicKey)
            ->and(Crypto::keys()->ed25519()->publicFromConfig('tokens.ed.public')->publicKey)->toBe($key->publicKey)
            ->and(Crypto::keys()->ed25519()->privateFromConfig('tokens.ed.secret')->secretKey)->toBe($key->secretKey);
    })->skip(fn (): bool => ! function_exists('sodium_crypto_sign_keypair'), 'ext-sodium not loaded');

    it('generates on first boot and reloads the same key after', function (): void {
        $first = Crypto::keys()->ed25519()->fromStorageOrGenerate('keys', 'ed.key');
        $again = Crypto::keys()->ed25519()->fromStorageOrGenerate('keys', 'ed.key');

        expect(Storage::disk('keys')->get('ed.key'))->toBe($first->secretKey)
            ->and($again->publicKey)->toBe($first->publicKey);
    })->skip(fn (): bool => ! function_exists('sodium_crypto_sign_keypair'), 'ext-sodium not loaded');
});

describe('Crypto::keys()->hmac()', function (): void {
    it('validates a string secret exactly as HmacSecret does', function (): void {
        $material = random_bytes(32);

        expect(Crypto::keys()->hmac()->fromString($material)->value)->toBe($material);

        Crypto::keys()->hmac()->fromString(keyPem('rsa-public'));
    })->throws(WeakKeyException::class);

    it('generates a secret of the requested length', function (): void {
        expect(strlen(Crypto::keys()->hmac()->generate()->value))->toBe(32)
            ->and(strlen(Crypto::keys()->hmac()->generate(64)->value))->toBe(64);
    });

    it('loads from a disk and from your config', function (): void {
        $material = random_bytes(40);
        Storage::disk('keys')->put('hmac.key', $material);
        config(['services.webhook.secret' => $material]);

        expect(Crypto::keys()->hmac()->fromStorage('keys', 'hmac.key')->value)->toBe($material)
            ->and(Crypto::keys()->hmac()->fromConfig('services.webhook.secret')->value)->toBe($material);
    });

    it('generates on first boot and reloads the same secret after', function (): void {
        $first = Crypto::keys()->hmac()->fromStorageOrGenerate('keys', 'hmac.key', 48);
        $again = Crypto::keys()->hmac()->fromStorageOrGenerate('keys', 'hmac.key');

        expect(strlen($first->value))->toBe(48)
            ->and(Storage::disk('keys')->get('hmac.key'))->toBe($first->value)
            ->and($again->value)->toBe($first->value);
    });
});

describe('Crypto::random()', function (): void {
    it('draws every token shape', function (): void {
        $secret = Crypto::random()->secret();

        expect(strlen(Crypto::random()->bytes(32)))->toBe(32)
            ->and(Crypto::random()->token())->toMatch('/^[A-Za-z0-9_-]{40}$/')
            ->and(Crypto::random()->token(64))->toHaveLength(64)
            ->and(Crypto::random()->numeric(6))->toMatch('/^\d{6}$/')
            ->and(Crypto::random()->alphanumeric(12))->toMatch('/^[0-9A-Za-z]{12}$/')
            ->and(Crypto::random()->fromAlphabet('AB', 16))->toMatch('/^[AB]{16}$/')
            ->and($secret)->toMatch('/^[A-Z2-7]{32}$/')
            ->and(Crypto::random()->secret(16))->toHaveLength(16)
            ->and(strlen(Crypto::base32Decode($secret)))->toBe(20);
    });

    it('keeps the length guards', function (Closure $call): void {
        $call();
    })->with([
        'bytes' => [fn () => Crypto::random()->bytes(0)],
        'token' => [fn () => Crypto::random()->token(8)],
        'numeric' => [fn () => Crypto::random()->numeric(0)],
        'alphanumeric' => [fn () => Crypto::random()->alphanumeric(0)],
        'alphabet' => [fn () => Crypto::random()->fromAlphabet('', 8)],
        'secret' => [fn () => Crypto::random()->secret(0)],
    ])->throws(InvalidLengthException::class);
});

describe('Crypto::x509()', function (): void {
    it('parses the same certificate from PEM, DER and base64', function (): void {
        $leaf = TestCertificates::chain()->leaf();

        $fromPem = Crypto::x509()->fromPem($leaf->pem());

        expect($fromPem)->toBeInstanceOf(Certificate::class)
            ->and($fromPem->equals($leaf))->toBeTrue()
            ->and(Crypto::x509()->fromDer($leaf->der())->equals($leaf))->toBeTrue()
            ->and(Crypto::x509()->fromBase64($leaf->base64())->equals($leaf))->toBeTrue();
    });

    it('builds the same chain from every input shape', function (): void {
        $fixture = TestCertificates::chain();
        $pems = array_map(static fn (Certificate $c): string => $c->pem(), $fixture->chain->certificates());
        $expected = $fixture->chain->fingerprints();

        $chains = [
            Crypto::x509()->chain()->fromX5c($fixture->x5c()),
            Crypto::x509()->chain()->fromPems($pems),
            Crypto::x509()->chain()->fromPemBundle($fixture->pemBundle()),
            Crypto::x509()->chain()->fromCertificates($fixture->chain->certificates()),
        ];

        foreach ($chains as $chain) {
            expect($chain)->toBeInstanceOf(Chain::class)
                ->and($chain->isLinked())->toBeTrue()
                ->and($chain->fingerprints())->toBe($expected);
        }
    });

    it('fails with the module\'s typed errors', function (): void {
        expect(fn () => Crypto::x509()->fromPem('nope'))->toThrow(MalformedCertificateException::class)
            ->and(fn () => Crypto::x509()->chain()->fromPems([]))->toThrow(InvalidChainException::class);

        Crypto::x509()->chain()->fromCertificates([]);
    })->throws(InvalidChainException::class);
});

describe('Crypto::ecDer()', function (): void {
    it('round-trips a raw signature exactly as Der does', function (int $coordBytes): void {
        $raw = random_bytes($coordBytes * 2);

        $der = Crypto::ecDer()->fromRaw($raw, $coordBytes);

        expect($der)->toBe(Der::fromRaw($raw, $coordBytes))
            ->and(Crypto::ecDer()->isValid($der))->toBeTrue()
            ->and(Crypto::ecDer()->toRaw($der, $coordBytes))->toBe($raw);
    })->with([32, 48, 66]);

    it('defaults to P-256 and rejects junk', function (): void {
        $raw = random_bytes(64);

        expect(Crypto::ecDer()->toRaw(Crypto::ecDer()->fromRaw($raw)))->toBe($raw)
            ->and(Crypto::ecDer()->isValid('junk'))->toBeFalse()
            ->and(fn () => Crypto::ecDer()->toRaw('junk'))->toThrow(InvalidSignatureException::class);

        Crypto::ecDer()->fromRaw('short');
    })->throws(InvalidSignatureException::class);
});

it('keeps the flat shortcuts on the same code path as the sub-accessors', function (): void {
    $fixture = TestCertificates::chain();

    expect(Crypto::certificate($fixture->leaf()->pem())->equals(Crypto::x509()->fromPem($fixture->leaf()->pem())))->toBeTrue()
        ->and(Crypto::chainFromX5c($fixture->x5c())->fingerprints())->toBe(Crypto::x509()->chain()->fromX5c($fixture->x5c())->fingerprints())
        ->and(Crypto::generateHmacSecret(40))->toBeInstanceOf(HmacSecret::class)
        ->and(Crypto::randomSecret(8))->toMatch('/^[A-Z2-7]{8}$/');
});
