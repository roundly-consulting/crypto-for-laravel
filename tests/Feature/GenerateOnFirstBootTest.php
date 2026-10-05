<?php

declare(strict_types=1);

use Illuminate\Filesystem\FilesystemAdapter;
use Illuminate\Filesystem\LocalFilesystemAdapter;
use Illuminate\Support\Facades\Storage;
use League\Flysystem\Filesystem as Flysystem;
use League\Flysystem\Local\LocalFilesystemAdapter as LocalAdapter;
use League\Flysystem\UnableToSetVisibility;
use RoundlyConsulting\Crypto\Signature\Key\EcKey;
use RoundlyConsulting\Crypto\Signature\Key\HmacSecret;
use RoundlyConsulting\Crypto\Signature\Key\OkpKey;
use RoundlyConsulting\Crypto\Signature\Key\RsaKey;
use RoundlyConsulting\Crypto\Signature\KeyLoadException;

/*
 * `fromStorageOrGenerate()` runs on every boot of every process. The first boots
 * of several processes race; the key they end up signing with must be the one
 * on disk, and that key must never be readable before it is private.
 */

beforeEach(fn () => Storage::fake('keys'));

dataset('first boots', [
    'hmac' => ['hmac'],
    'ec' => ['ec'],
    'rsa' => ['rsa'],
    ...(function_exists('sodium_crypto_sign_keypair') ? ['okp' => ['okp']] : []),
]);

function firstBoot(string $type, string $path = 'k.key'): HmacSecret|EcKey|RsaKey|OkpKey
{
    return match ($type) {
        'hmac' => HmacSecret::fromStorageOrGenerate('keys', $path),
        'ec' => EcKey::fromStorageOrGenerate('keys', $path),
        'rsa' => RsaKey::fromStorageOrGenerate('keys', $path),
        'okp' => OkpKey::fromStorageOrGenerate('keys', $path),
    };
}

function persistedKey(string $type): HmacSecret|EcKey|RsaKey|OkpKey
{
    return match ($type) {
        'hmac' => HmacSecret::fromStorage('keys', 'k.key'),
        'ec' => EcKey::privateFromStorage('keys', 'k.key'),
        'rsa' => RsaKey::privateFromStorage('keys', 'k.key'),
        'okp' => OkpKey::secretKeyFromStorage('keys', 'k.key'),
    };
}

function keyIdentity(HmacSecret|EcKey|RsaKey|OkpKey $key): string
{
    return match (true) {
        $key instanceof HmacSecret => $key->value,
        $key instanceof OkpKey => $key->publicKey,
        default => $key->publicPem(),
    };
}

/**
 * The `keys` disk, rebuilt so its `exists()` runs `$afterFirstCheck` once, right
 * after it has looked: the moment a rival process can finish its whole first
 * boot. `$local: false` gives the same files behind a disk that is not a local
 * one, the way an object store is.
 */
function racingDisk(Closure $afterFirstCheck, bool $local = true): FilesystemAdapter
{
    $fake = Storage::fake('keys');
    $arguments = [$fake->getDriver(), $fake->getAdapter(), $fake->getConfig()];

    $disk = $local
        ? new class(...$arguments) extends LocalFilesystemAdapter
        {
            public ?Closure $afterFirstCheck = null;

            public function exists($path)
            {
                $exists = parent::exists($path);

                if (($hook = $this->afterFirstCheck) !== null) {
                    $this->afterFirstCheck = null;
                    $hook();
                }

                return $exists;
            }
        }
    : new class(...$arguments) extends FilesystemAdapter
    {
        public ?Closure $afterFirstCheck = null;

        public function exists($path)
        {
            $exists = parent::exists($path);

            if (($hook = $this->afterFirstCheck) !== null) {
                $this->afterFirstCheck = null;
                $hook();
            }

            return $exists;
        }
    };

    $disk->afterFirstCheck = $afterFirstCheck;
    Storage::set('keys', $disk);

    return $disk;
}

/**
 * The `keys` disk on a local adapter that calls `$onSetVisibility` every time it
 * is asked to change a file's permissions — as Flysystem's own write does right
 * after it has created the file.
 */
function visibilityDisk(Closure $onSetVisibility, bool $throws = false): LocalFilesystemAdapter
{
    $root = Storage::fake('keys')->path('');

    $adapter = new class($root, $onSetVisibility) extends LocalAdapter
    {
        public function __construct(string $root, private readonly Closure $onSetVisibility)
        {
            parent::__construct($root);
        }

        public function setVisibility(string $path, string $visibility): void
        {
            ($this->onSetVisibility)($path);

            parent::setVisibility($path, $visibility);
        }
    };

    $disk = new LocalFilesystemAdapter(new Flysystem($adapter), $adapter, ['root' => $root, 'throw' => $throws]);
    Storage::set('keys', $disk);

    return $disk;
}

it('hands every racing first boot the key that ends up on disk', function (string $type, bool $local): void {
    $rival = null;
    racingDisk(function () use (&$rival, $type): void {
        $rival = firstBoot($type);
    }, $local);

    $mine = firstBoot($type);
    $persisted = keyIdentity(persistedKey($type));

    expect($rival)->not->toBeNull()
        ->and(keyIdentity($mine))->toBe($persisted)
        ->and(keyIdentity($rival))->toBe($persisted);
})->with('first boots')->with(['local disk' => [true], 'remote disk' => [false]]);

it('leaves nothing at the key path when the disk cannot make the key private', function (string $type, bool $throws): void {
    $disk = visibilityDisk(function (): never {
        throw UnableToSetVisibility::atLocation('k.key', 'chmod refused');
    }, $throws);

    expect(fn (): mixed => firstBoot($type))->toThrow(KeyLoadException::class, 'could not be written');

    // Nor a temporary copy of it: only the lock file stays, so the next boot
    // generates a fresh key instead of adopting one that was never private.
    expect($disk->exists('k.key'))->toBeFalse()
        ->and($disk->allFiles())->toBe(['k.key.lock']);
})->with('first boots')->with(['disk reports false' => [false], 'disk throws' => [true]]);

it('never shows a key at its path, or readable by others, before it is private', function (string $type): void {
    $root = Storage::fake('keys')->path('');
    $observed = [];

    visibilityDisk(function (string $path) use (&$observed, $root): void {
        clearstatcache();

        $observed[] = [
            'mode' => fileperms($root.'/'.$path) & 0777,
            'at key path' => file_exists($root.'/k.key'),
        ];
    });

    firstBoot($type);

    expect($observed)->not->toBeEmpty()
        ->each->toBe(['mode' => 0600, 'at key path' => false]);
})->with('first boots');

it('creates the directories of a nested key path', function (): void {
    $key = HmacSecret::fromStorageOrGenerate('keys', 'nested/deeper/k.key');

    expect(Storage::disk('keys')->get('nested/deeper/k.key'))->toBe($key->value)
        ->and(Storage::disk('keys')->getVisibility('nested/deeper/k.key'))->toBe('private')
        ->and(Storage::disk('keys')->allFiles())->toBe(['nested/deeper/k.key', 'nested/deeper/k.key.lock']);
});

it('reports a key directory that cannot be created', function (bool $throws): void {
    $disk = Storage::fake('keys', ['throw' => $throws]);
    $disk->put('blocker', 'a file where the directory should be');

    expect(fn (): mixed => HmacSecret::fromStorageOrGenerate('keys', 'blocker/k.key'))
        ->toThrow(KeyLoadException::class, 'could not be written to disk [keys] at [blocker/k.key]');
})->with(['disk reports false' => [false], 'disk throws' => [true]]);

describe('a key directory the process may not write', function (): void {
    $asRoot = fn (): bool => function_exists('posix_geteuid') && posix_geteuid() === 0;

    afterEach(function (): void {
        chmod(Storage::disk('keys')->path(''), 0755);
    });

    it('refuses to generate when the lock cannot be taken', function (): void {
        $root = Storage::fake('keys')->path('');
        chmod($root, 0555);

        expect(fn (): mixed => HmacSecret::fromStorageOrGenerate('keys', 'k.key'))
            ->toThrow(KeyLoadException::class, 'Key generation for disk [keys] at [k.key] could not be locked.');
    })->skip($asRoot, 'root ignores file permissions');

    it('never writes the key outside its own directory', function (): void {
        // The lock file exists, so the lock is taken; the temporary file is the
        // first thing that cannot be created, and tempnam() would fall back to
        // the system temp directory — a rename from there is not atomic.
        $disk = Storage::fake('keys');
        $disk->put('k.key.lock', '');
        chmod($disk->path(''), 0555);

        expect(fn (): mixed => HmacSecret::fromStorageOrGenerate('keys', 'k.key'))
            ->toThrow(KeyLoadException::class, 'could not be written to disk [keys] at [k.key]');

        expect($disk->exists('k.key'))->toBeFalse();
    })->skip($asRoot, 'root ignores file permissions');
});

it('generates into a key directory reached through a symlink', function (): void {
    // Zero-downtime deploys link `storage/` to a shared directory.
    $base = Storage::fake('keys')->path('');
    mkdir($base.'/shared');
    symlink($base.'/shared', $base.'/current');
    Storage::set('keys', Storage::build(['driver' => 'local', 'root' => $base.'/current']));

    $key = HmacSecret::fromStorageOrGenerate('keys', 'k.key');

    expect(file_get_contents($base.'/shared/k.key'))->toBe($key->value)
        ->and(fileperms($base.'/shared/k.key') & 0777)->toBe(0600);
});
