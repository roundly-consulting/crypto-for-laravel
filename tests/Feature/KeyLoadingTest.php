<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Storage;
use RoundlyConsulting\Crypto\Signature\Algorithm;
use RoundlyConsulting\Crypto\Signature\Key\EcKey;
use RoundlyConsulting\Crypto\Signature\Key\HmacSecret;
use RoundlyConsulting\Crypto\Signature\Key\OkpKey;
use RoundlyConsulting\Crypto\Signature\Key\RsaKey;
use RoundlyConsulting\Crypto\Signature\KeyLoadException;
use RoundlyConsulting\Crypto\Signature\WeakKeyException;

beforeEach(function (): void {
    Storage::fake('keys');
});

$sodium = fn (): bool => function_exists('sodium_crypto_sign_keypair');

// ── HmacSecret ──────────────────────────────────────────────────────────────

describe('HmacSecret::generate', function (): void {
    it('generates a strong secret of the default length', function (): void {
        $secret = HmacSecret::generate();

        expect(strlen($secret->value))->toBe(32);
    });

    it('honours a custom byte length', function (): void {
        expect(strlen(HmacSecret::generate(64)->value))->toBe(64);
    });

    it('rejects fewer than 32 bytes', function (): void {
        HmacSecret::generate(16);
    })->throws(WeakKeyException::class);
});

describe('HmacSecret loading', function (): void {
    it('loads a secret from storage', function (): void {
        Storage::disk('keys')->put('hmac.key', str_repeat('a', 20).str_repeat('b', 20));

        expect(HmacSecret::fromStorage('keys', 'hmac.key')->value)->toHaveLength(40);
    });

    it('throws when the storage file is missing', function (): void {
        HmacSecret::fromStorage('keys', 'nope.key');
    })->throws(KeyLoadException::class);

    it('validates material read from storage', function (): void {
        Storage::disk('keys')->put('weak.key', 'too-short');

        HmacSecret::fromStorage('keys', 'weak.key');
    })->throws(WeakKeyException::class);

    it('loads a secret from config', function (): void {
        config(['services.webhook.secret' => str_repeat('a', 20).str_repeat('b', 20)]);

        expect(HmacSecret::fromConfig('services.webhook.secret')->value)->toHaveLength(40);
    });

    it('throws when the config value is missing', function (): void {
        HmacSecret::fromConfig('services.webhook.missing');
    })->throws(KeyLoadException::class);

    it('throws when the config value is empty', function (): void {
        config(['services.webhook.secret' => '']);

        HmacSecret::fromConfig('services.webhook.secret');
    })->throws(KeyLoadException::class);

    it('throws when the config value is not a string', function (): void {
        config(['services.webhook.secret' => 1234]);

        HmacSecret::fromConfig('services.webhook.secret');
    })->throws(KeyLoadException::class);
});

describe('HmacSecret::fromStorageOrGenerate', function (): void {
    it('generates and persists a secret with private visibility when missing', function (): void {
        $secret = HmacSecret::fromStorageOrGenerate('keys', 'hmac.key');

        expect(Storage::disk('keys')->exists('hmac.key'))->toBeTrue()
            ->and(Storage::disk('keys')->get('hmac.key'))->toBe($secret->value)
            ->and(Storage::disk('keys')->getVisibility('hmac.key'))->toBe('private');
    });

    it('reloads the same secret on a second call', function (): void {
        $first = HmacSecret::fromStorageOrGenerate('keys', 'hmac.key');
        $second = HmacSecret::fromStorageOrGenerate('keys', 'hmac.key');

        expect($second->value)->toBe($first->value);
    });

    it('never overwrites existing-but-invalid material', function (): void {
        Storage::disk('keys')->put('hmac.key', 'too-short');

        expect(fn () => HmacSecret::fromStorageOrGenerate('keys', 'hmac.key'))
            ->toThrow(WeakKeyException::class);

        expect(Storage::disk('keys')->get('hmac.key'))->toBe('too-short');
    });
});

// ── RsaKey ──────────────────────────────────────────────────────────────────

describe('RsaKey loading', function (): void {
    it('loads public and private keys from storage', function (): void {
        Storage::disk('keys')->put('rsa-pub.pem', keyPem('rsa-public'));
        Storage::disk('keys')->put('rsa-priv.pem', keyPem('rsa-private'));

        expect(RsaKey::publicFromStorage('keys', 'rsa-pub.pem')->algorithm())->toBe(Algorithm::RS256)
            ->and(RsaKey::privateFromStorage('keys', 'rsa-priv.pem')->isPrivate)->toBeTrue();
    });

    it('loads public and private keys from config', function (): void {
        config(['tokens.public' => keyPem('rsa-public'), 'tokens.private' => keyPem('rsa-private')]);

        expect(RsaKey::publicFromConfig('tokens.public')->isPrivate)->toBeFalse()
            ->and(RsaKey::privateFromConfig('tokens.private')->isPrivate)->toBeTrue();
    });

    it('throws when the storage file is missing', function (): void {
        RsaKey::privateFromStorage('keys', 'nope.pem');
    })->throws(KeyLoadException::class);

    it('throws when the config value is missing', function (): void {
        RsaKey::publicFromConfig('tokens.missing');
    })->throws(KeyLoadException::class);
});

describe('RsaKey::fromStorageOrGenerate', function (): void {
    it('generates and persists a private PEM when missing', function (): void {
        $key = RsaKey::fromStorageOrGenerate('keys', 'rsa.key');

        expect($key->isPrivate)->toBeTrue()
            ->and(Storage::disk('keys')->getVisibility('rsa.key'))->toBe('private')
            ->and(Storage::disk('keys')->get('rsa.key'))->toContain('PRIVATE KEY');
    });

    it('reloads the same key on a second call', function (): void {
        $first = RsaKey::fromStorageOrGenerate('keys', 'rsa.key');
        $second = RsaKey::fromStorageOrGenerate('keys', 'rsa.key');

        expect($first->publicPem())->toBe($second->publicPem());
    });

    it('never overwrites existing-but-invalid material', function (): void {
        Storage::disk('keys')->put('rsa.key', 'not a pem');

        expect(fn () => RsaKey::fromStorageOrGenerate('keys', 'rsa.key'))
            ->toThrow(KeyLoadException::class);

        expect(Storage::disk('keys')->get('rsa.key'))->toBe('not a pem');
    });

    it('derives a loadable public PEM from a generated key', function (): void {
        $key = RsaKey::fromStorageOrGenerate('keys', 'rsa.key');

        expect(RsaKey::public($key->publicPem())->algorithm())->toBe(Algorithm::RS256);
    });
});

// ── EcKey ───────────────────────────────────────────────────────────────────

describe('EcKey loading', function (): void {
    it('loads public and private keys from storage', function (): void {
        Storage::disk('keys')->put('ec-pub.pem', keyPem('ec-public'));
        Storage::disk('keys')->put('ec-priv.pem', keyPem('ec-private'));

        expect(EcKey::publicFromStorage('keys', 'ec-pub.pem')->algorithm())->toBe(Algorithm::ES256)
            ->and(EcKey::privateFromStorage('keys', 'ec-priv.pem')->isPrivate)->toBeTrue();
    });

    it('loads public and private keys from config', function (): void {
        config(['tokens.public' => keyPem('ec-public'), 'tokens.private' => keyPem('ec-private')]);

        expect(EcKey::publicFromConfig('tokens.public')->curve)->toBe('P-256')
            ->and(EcKey::privateFromConfig('tokens.private')->isPrivate)->toBeTrue();
    });

    it('throws when the storage file is missing', function (): void {
        EcKey::publicFromStorage('keys', 'nope.pem');
    })->throws(KeyLoadException::class);

    it('throws when the config value is missing', function (): void {
        EcKey::privateFromConfig('tokens.missing');
    })->throws(KeyLoadException::class);
});

describe('EcKey::fromStorageOrGenerate', function (): void {
    it('generates and persists a private PEM when missing', function (): void {
        $key = EcKey::fromStorageOrGenerate('keys', 'ec.key');

        expect($key->isPrivate)->toBeTrue()
            ->and($key->curve)->toBe('P-256')
            ->and(Storage::disk('keys')->getVisibility('ec.key'))->toBe('private');
    });

    it('honours a custom curve', function (): void {
        $key = EcKey::fromStorageOrGenerate('keys', 'ec.key', 'P-384');

        expect($key->curve)->toBe('P-384');
    });

    it('reloads the same key on a second call', function (): void {
        $first = EcKey::fromStorageOrGenerate('keys', 'ec.key');
        $second = EcKey::fromStorageOrGenerate('keys', 'ec.key');

        expect($first->publicPem())->toBe($second->publicPem());
    });

    it('never overwrites existing-but-invalid material', function (): void {
        Storage::disk('keys')->put('ec.key', 'not a pem');

        expect(fn () => EcKey::fromStorageOrGenerate('keys', 'ec.key'))
            ->toThrow(KeyLoadException::class);

        expect(Storage::disk('keys')->get('ec.key'))->toBe('not a pem');
    });

    it('derives a loadable public PEM from a generated key', function (): void {
        $key = EcKey::fromStorageOrGenerate('keys', 'ec.key');

        expect(EcKey::public($key->publicPem())->algorithm())->toBe(Algorithm::ES256);
    });
});

// ── OkpKey ──────────────────────────────────────────────────────────────────

describe('OkpKey loading', function () use ($sodium): void {
    it('loads a raw public key from storage', function (): void {
        Storage::disk('keys')->put('okp-pub.bin', str_repeat("\x01", 32));

        expect(OkpKey::ed25519FromStorage('keys', 'okp-pub.bin')->publicKey)->toHaveLength(32);
    });

    it('loads a raw public key from config', function (): void {
        config(['tokens.okp' => str_repeat("\x02", 32)]);

        expect(OkpKey::ed25519FromConfig('tokens.okp')->secretKey)->toBeNull();
    });

    it('throws when the public storage file is missing', function (): void {
        OkpKey::ed25519FromStorage('keys', 'nope.bin');
    })->throws(KeyLoadException::class);

    it('throws when the public config value is missing', function (): void {
        OkpKey::ed25519FromConfig('tokens.missing');
    })->throws(KeyLoadException::class);

    it('loads a secret key from storage', function (): void {
        $generated = OkpKey::generate();
        Storage::disk('keys')->put('okp-sec.bin', (string) $generated->secretKey);

        expect(OkpKey::secretKeyFromStorage('keys', 'okp-sec.bin')->publicKey)
            ->toBe($generated->publicKey);
    })->skip(fn (): bool => ! $sodium(), 'ext-sodium not loaded');

    it('loads a secret key from config', function (): void {
        $generated = OkpKey::generate();
        config(['tokens.sec' => (string) $generated->secretKey]);

        expect(strlen((string) OkpKey::secretKeyFromConfig('tokens.sec')->secretKey))->toBe(64);
    })->skip(fn (): bool => ! $sodium(), 'ext-sodium not loaded');
});

describe('OkpKey::fromStorageOrGenerate', function () use ($sodium): void {
    it('generates and persists a 64-byte secret when missing', function (): void {
        $key = OkpKey::fromStorageOrGenerate('keys', 'okp.key');

        expect(strlen((string) $key->secretKey))->toBe(64)
            ->and(Storage::disk('keys')->get('okp.key'))->toBe((string) $key->secretKey)
            ->and(Storage::disk('keys')->getVisibility('okp.key'))->toBe('private');
    })->skip(fn (): bool => ! $sodium(), 'ext-sodium not loaded');

    it('reloads the same key on a second call', function (): void {
        $first = OkpKey::fromStorageOrGenerate('keys', 'okp.key');
        $second = OkpKey::fromStorageOrGenerate('keys', 'okp.key');

        expect($second->publicKey)->toBe($first->publicKey);
    })->skip(fn (): bool => ! $sodium(), 'ext-sodium not loaded');

    it('never overwrites existing-but-invalid material', function (): void {
        Storage::disk('keys')->put('okp.key', 'short');

        expect(fn () => OkpKey::fromStorageOrGenerate('keys', 'okp.key'))
            ->toThrow(KeyLoadException::class);

        expect(Storage::disk('keys')->get('okp.key'))->toBe('short');
    })->skip(fn (): bool => ! $sodium(), 'ext-sodium not loaded');
});
