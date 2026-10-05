<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Signature\Key\HmacSecret;
use RoundlyConsulting\Crypto\Signature\Key\OkpKey;

/**
 * A reference to a key's secret buffer. The properties are `private(set)`, so
 * only the class's own scope may take one; the bound reader is dropped before
 * returning, so the alias does not keep the holder alive.
 */
function &secretBuffer(object $holder, string $property): ?string
{
    $reader = Closure::bind(function &() use ($property): ?string {
        return $this->{$property};
    }, $holder, $holder::class);

    $buffer = &$reader();

    return $buffer;
}

it('wipes an HMAC secret from memory when the holder is destroyed', function (): void {
    $raw = str_repeat('A', 20).str_repeat('B', 20);
    $secret = HmacSecret::fromString($raw);

    // Alias the buffer, then destroy the holder; __destruct memzeroes it, so the
    // aliased value is no longer the secret.
    $alias = &secretBuffer($secret, 'value');
    expect($alias)->toBe($raw);

    unset($secret);

    expect($alias)->not->toBe($raw)
        ->and($alias === null || $alias === '')->toBeTrue();
})->skip(fn (): bool => ! function_exists('sodium_memzero'), 'ext-sodium not loaded');

it('wipes an Ed25519 secret key when the holder is destroyed', function (): void {
    $key = OkpKey::generate();
    $secret = (string) $key->secretKey;

    $alias = &secretBuffer($key, 'secretKey');
    expect($alias)->toBe($secret);

    unset($key);

    expect($alias)->not->toBe($secret)
        ->and($alias === null || $alias === '')->toBeTrue();
})->skip(fn (): bool => ! function_exists('sodium_crypto_sign_keypair'), 'ext-sodium not loaded');

it('destroys a public-only OKP key without attempting a wipe', function (): void {
    // A public-only key carries no secret, so __destruct must be a clean no-op.
    $key = OkpKey::ed25519(str_repeat("\x01", 32));

    expect($key->secretKey)->toBeNull();

    unset($key);

    expect(true)->toBeTrue();
});

it('keeps a validated secret out of reach of outside writes', function (Closure $write): void {
    // The guards run once, at construction: a later write would sign with a
    // key nothing ever checked (an empty HMAC key, another pair's Ed25519 key).
    expect($write)->toThrow(Error::class, 'Cannot modify private(set) property');
})->with([
    'HmacSecret::$value' => [fn () => HmacSecret::generate()->value = ''],
    ...(function_exists('sodium_crypto_sign_keypair') ? [
        'OkpKey::$secretKey' => [fn () => OkpKey::generate()->secretKey = (string) OkpKey::generate()->secretKey],
    ] : []),
]);
