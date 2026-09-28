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
 * The COSE_Key bytes of a committed vector (es256 / rs256 / eddsa).
 */
function coseBytes(string $name): string
{
    /** @var array{cose: string} $vector */
    $vector = cryptoVectors()[$name];

    return (string) hex2bin($vector['cose']);
}

/**
 * Encode a COSE_Key-shaped CBOR map: integer labels, integer or BYTE-string values.
 *
 * @param  array<int, int|string>  $map
 */
function coseCbor(array $map): string
{
    $head = static fn (int $major, int $argument): string => match (true) {
        $argument < 24 => chr($major << 5 | $argument),
        $argument < 0x100 => chr($major << 5 | 24).chr($argument),
        default => chr($major << 5 | 25).pack('n', $argument),
    };
    $integer = static fn (int $value): string => $value >= 0 ? $head(0, $value) : $head(1, -1 - $value);

    $bytes = $head(5, count($map));

    foreach ($map as $label => $value) {
        $bytes .= $integer($label).(is_int($value) ? $integer($value) : $head(2, strlen($value)).$value);
    }

    return $bytes;
}
