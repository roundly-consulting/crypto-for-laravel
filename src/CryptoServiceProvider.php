<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto;

use Illuminate\Foundation\Console\AboutCommand;
use Illuminate\Support\ServiceProvider;
use RoundlyConsulting\Crypto\Asn1\DerDecoder;
use RoundlyConsulting\Crypto\Cose\CborDecoder;
use RoundlyConsulting\Crypto\Jose\Jws;
use RoundlyConsulting\Crypto\Signature\KeyVerifier;

/**
 * Registers the package's key-less, stateless services as container singletons
 * plus the optional Crypto facade target.
 *
 * This provider is deliberately minimal (the package is zero-config): it ships
 * no config file, no migrations, no views, no routes, and it never constructs an
 * object that holds a secret. Anything keyed is built by the consumer's own
 * service provider from the consumer's own config.
 */
final class CryptoServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(Jws::class, static fn (): Jws => new Jws);
        $this->app->singleton(CborDecoder::class, static fn (): CborDecoder => new CborDecoder);
        $this->app->singleton(DerDecoder::class, static fn (): DerDecoder => new DerDecoder);
        $this->app->singleton(KeyVerifier::class, static fn (): KeyVerifier => new KeyVerifier);
        $this->app->singleton(CryptoManager::class, static fn (): CryptoManager => new CryptoManager);
    }

    public function boot(): void
    {
        if (class_exists(AboutCommand::class)) {
            AboutCommand::add('Crypto', [
                'JOSE / JWS' => 'enabled',
                'JWK / X.509' => 'enabled',
                'EdDSA (Ed25519)' => function_exists('sodium_crypto_sign_verify_detached') ? 'available' : 'needs ext-sodium',
            ]);
        }
    }
}
