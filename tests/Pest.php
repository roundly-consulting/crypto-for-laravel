<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Tests\TestCase;

uses(TestCase::class)->in(__DIR__);

// Load the opt-in expectations the package ships for consumers, exactly as a
// consumer would from their own tests/Pest.php, so they are exercised here too.
require __DIR__.'/../src/Testing/pest-expectations.php';

/**
 * Read a raw fixture file from tests/Fixtures.
 */
function readFixture(string $path): string
{
    return (string) file_get_contents(__DIR__.'/Fixtures/'.$path);
}

/**
 * The committed static crypto vectors.
 *
 * @return array<string, mixed>
 */
function cryptoVectors(): array
{
    /** @var array<string, mixed> */
    return require __DIR__.'/Fixtures/crypto-vectors.php';
}

/**
 * A committed key PEM by name (without extension).
 */
function keyPem(string $name): string
{
    return readFixture('keys/'.$name.'.pem');
}

/**
 * Decode a JSON fixture into an array.
 *
 * @return array<string, mixed>
 */
function jsonFixture(string $path): array
{
    /** @var array<string, mixed> */
    return json_decode(readFixture($path), true, 512, JSON_THROW_ON_ERROR);
}

/**
 * The decoded COSE_Key map for a committed vector (es256 / rs256 / eddsa).
 *
 * @return array<int|string, mixed>
 */
function coseMap(string $name): array
{
    /** @var array{cose: string} $vector */
    $vector = cryptoVectors()[$name];
    $decoded = (new RoundlyConsulting\Crypto\Cose\CborDecoder)->decode(hex2bin($vector['cose']));

    /** @var array<int|string, mixed> */
    return $decoded;
}
