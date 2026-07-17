<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migrator;
use Illuminate\Support\ServiceProvider;
use RoundlyConsulting\Crypto\CryptoServiceProvider;
use RoundlyConsulting\PackageToolkit\Package;
use RoundlyConsulting\PackageToolkit\PackageServiceProvider;

/**
 * The package's `Package` declaration, built exactly as the provider builds it.
 */
function cryptoPackage(): Package
{
    $package = (new Package)->setBasePath(dirname(__DIR__, 2));

    (new CryptoServiceProvider(app()))->configurePackage($package);

    return $package;
}

/**
 * Every string literal in a `src/` file, read from the PHP tokenizer — so a
 * comment or a docblock naming a config key is NOT mistaken for a read.
 *
 * @return list<string>
 */
function cryptoSourceStrings(): array
{
    $strings = [];

    $files = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator((string) realpath(__DIR__.'/../../src'), FilesystemIterator::SKIP_DOTS),
    );

    foreach ($files as $file) {
        if ($file->getExtension() !== 'php') {
            continue;
        }

        foreach (token_get_all((string) file_get_contents($file->getPathname())) as $token) {
            if (is_array($token) && $token[0] === T_CONSTANT_ENCAPSED_STRING) {
                $strings[] = trim($token[1], "'\"");
            }
        }
    }

    return $strings;
}

it('builds on the package toolkit', function (): void {
    expect(new CryptoServiceProvider(app()))->toBeInstanceOf(PackageServiceProvider::class);
});

it('declares the zero-config surface and nothing else', function (): void {
    $package = cryptoPackage();

    expect($package->name)->toBe('crypto')
        ->and($package->configFiles)->toBe([])
        ->and($package->hasMigrations)->toBeFalse()
        ->and($package->migrationStubs)->toBe([])
        ->and($package->hasViews)->toBeFalse()
        ->and($package->hasTranslations)->toBeFalse()
        ->and($package->routes)->toBe([])
        ->and($package->commands)->toBe([])
        ->and($package->publishableStubs)->toBe([])
        // The `Crypto` alias is composer-declared; the provider must not add a second.
        ->and($package->facadeAliases)->toBe([])
        ->and($package->aboutContributions)->toHaveCount(1)
        ->and($package->aboutContributions[0]->section)->toBe('Crypto');
});

it('registers no publish group of its own', function (): void {
    $groups = array_keys(ServiceProvider::publishableGroups());

    $crypto = array_values(array_filter($groups, fn (string $g): bool => str_starts_with($g, 'crypto')));

    expect($crypto)->toBe([]);
});

it('ships no migrations and never auto-loads any', function (): void {
    /** @var Migrator $migrator */
    $migrator = app('migrator');

    expect(is_dir(dirname(__DIR__, 2).'/database'))->toBeFalse()
        ->and(cryptoPackage()->hasMigrations)->toBeFalse();

    foreach ($migrator->paths() as $path) {
        expect($path)->not->toStartWith(dirname(__DIR__, 2).DIRECTORY_SEPARATOR);
    }
});

it('ships no config file and reads no crypto config key', function (): void {
    // Shipped-not-read: the package ships nothing, so there is nothing to strand.
    expect(is_dir(dirname(__DIR__, 2).'/config'))->toBeFalse();

    // Reads-not-shipped: no `src/` file may read a `crypto.*` key — the package's
    // own config namespace does not exist, so a read of it could never resolve.
    // Consumer-owned keys (`jwt.keys.private`, …) reach the `*FromConfig`
    // factories as arguments and are never literals here.
    $strings = cryptoSourceStrings();

    $ownKeys = array_values(array_filter($strings, fn (string $s): bool => str_starts_with($s, 'crypto.')));

    // The scrape really did read the source (guards against a silent no-op).
    expect($strings)->not->toBe([])
        ->and($ownKeys)->toBe([]);
});
