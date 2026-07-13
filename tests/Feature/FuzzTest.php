<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Asn1\DerDecoder;
use RoundlyConsulting\Crypto\Codec\Base32;
use RoundlyConsulting\Crypto\Codec\Base64;
use RoundlyConsulting\Crypto\Codec\Base64Url;
use RoundlyConsulting\Crypto\Codec\Hex;
use RoundlyConsulting\Crypto\Cose\AuthenticatorData;
use RoundlyConsulting\Crypto\Cose\CborDecoder;
use RoundlyConsulting\Crypto\Exceptions\CryptoException;
use RoundlyConsulting\Crypto\Jose\Jwk;
use RoundlyConsulting\Crypto\Jose\Jws;
use RoundlyConsulting\Crypto\Signature\Algorithm;
use RoundlyConsulting\Crypto\Signature\Ec\Der;
use RoundlyConsulting\Crypto\Signature\Hs;
use RoundlyConsulting\Crypto\Signature\Key\EcKey;
use RoundlyConsulting\Crypto\Signature\Key\HmacSecret;
use RoundlyConsulting\Crypto\Testing\TestCertificates;
use RoundlyConsulting\Crypto\X509\Certificate;
use RoundlyConsulting\Crypto\X509\Chain;

/*
 * Fuzz targets for the attacker-facing byte sinks. Each feeds random and
 * mutation-of-valid inputs into a decoder/verifier and asserts the ONLY things
 * that ever come back are the package's typed exceptions (CryptoException) or the
 * method's declared return — never a native PHP Error/warning, and always in
 * bounded time (depth/length caps guarantee termination).
 *
 * The per-target budget is short by default so CI stays fast; raise it for a
 * longer nightly run with CRYPTO_FUZZ_ITERATIONS=100000.
 */

function fuzzIterations(): int
{
    $env = getenv('CRYPTO_FUZZ_ITERATIONS');

    return $env === false ? 400 : max(1, (int) $env);
}

/**
 * Random plus mutated-seed byte strings.
 *
 * @return iterable<string>
 */
function fuzzCorpus(string $seed = ''): iterable
{
    $iterations = fuzzIterations();

    // The empty string is itself an edge case for every sink.
    yield '';

    for ($i = 0; $i < $iterations; $i++) {
        yield random_bytes(random_int(1, 96));

        if ($seed === '') {
            continue;
        }

        $mutated = $seed;
        $mutated[random_int(0, strlen($seed) - 1)] = chr(random_int(0, 255));

        yield $mutated;
        yield substr($seed, 0, random_int(0, strlen($seed)));
        yield $seed.random_bytes(random_int(1, 8));
    }
}

/**
 * Drive one sink over the corpus; a non-CryptoException Throwable escapes and
 * fails the test, which is exactly the property under test.
 *
 * @param  callable(string): mixed  $sink
 */
function fuzzSink(callable $sink, string $seed = ''): void
{
    $runs = 0;

    foreach (fuzzCorpus($seed) as $input) {
        try {
            $sink($input);
        } catch (CryptoException) {
            // The one permitted outcome besides a normal return.
        }

        $runs++;
    }

    expect($runs)->toBeGreaterThan(0);
}

it('never leaks a native error from JWS verify', function (): void {
    $verifier = new Hs(HmacSecret::fromString('0123456789abcdef0123456789abcdef!'), Algorithm::HS256);
    $jws = new Jws;
    $seed = $jws->sign(['kid' => 'k'], ['sub' => '1'], $verifier);

    fuzzSink(fn (string $input): mixed => $jws->verify($input, $verifier, Algorithm::HS256), $seed);
});

it('never leaks a native error from CBOR decode', function (): void {
    fuzzSink(fn (string $input): mixed => (new CborDecoder)->decode($input), hex2bin(cryptoVectors()['es256']['cose']));
});

it('never leaks a native error from DER decode', function (): void {
    // Seed with a real certificate's DER — the mutated corpus then walks every
    // tag/length boundary a hostile extension could aim at.
    $seed = TestCertificates::chain(length: 1)->leaf()->der();

    fuzzSink(function (string $input): mixed {
        $decoder = new DerDecoder;
        $decoder->decodeFirst($input);

        // The typed readers are attacker-facing too: whatever the tag turned out
        // to be, reading it as the wrong type must be a typed rejection.
        $element = $decoder->decode($input);
        $element->isNull();

        foreach ([$element->oid(...), $element->integer(...), $element->octetString(...), $element->boolean(...), $element->children(...)] as $reader) {
            try {
                $reader();
            } catch (CryptoException) {
                // The one permitted outcome.
            }
        }

        return $element;
    }, $seed);
});

it('never leaks a native error from authenticatorData parse', function (): void {
    fuzzSink(fn (string $input): mixed => AuthenticatorData::parse($input), hex2bin(cryptoVectors()['auth_data']['bytes']));
});

it('never leaks a native error from ECDSA DER parsing', function (): void {
    $seed = hex2bin(cryptoVectors()['es256']['sig_der']);

    fuzzSink(function (string $input): mixed {
        // Both the validity check and the raw conversion are attacker-facing.
        Der::isValid($input);

        return Der::toRaw($input, 32);
    }, $seed);
});

it('never leaks a native error from JWK parsing', function (): void {
    $seed = json_encode(Jwk::fromPublicKey(EcKey::generate())->toArray(), JSON_THROW_ON_ERROR);

    fuzzSink(fn (string $input): mixed => Jwk::fromJson($input), $seed);

    // The array entry point takes arbitrary decoded JSON, so fuzz the value
    // types too — a member that is an int, an array, or a bool must be a typed
    // rejection, never a TypeError.
    $members = Jwk::fromPublicKey(EcKey::generate())->toArray();
    $junk = [random_bytes(8), 42, 0.5, true, null, ['nested'], str_repeat('A', 9000)];

    foreach (array_keys($members) + ['d' => 'd', 'x5c' => 'x5c'] as $member) {
        foreach ($junk as $value) {
            try {
                Jwk::fromArray([...$members, (string) $member => $value]);
            } catch (CryptoException) {
                // The one permitted outcome.
            }
        }
    }

    expect(true)->toBeTrue();
});

it('never leaks a native error from certificate parsing', function (): void {
    $leaf = TestCertificates::chain(length: 1)->leaf();

    fuzzSink(fn (string $input): mixed => Certificate::fromPem($input), $leaf->pem());
    fuzzSink(fn (string $input): mixed => Certificate::fromDer($input), $leaf->der());
    fuzzSink(fn (string $input): mixed => Certificate::fromBase64($input), $leaf->base64());
    fuzzSink(fn (string $input): mixed => Chain::fromPemBundle($input), $leaf->pem());
});

it('never leaks a native error from x5c chain parsing', function (): void {
    $x5c = TestCertificates::chain()->x5c();

    // Mutated arrays: wrong lengths, huge entries, mixed valid and garbage.
    $corpora = [
        [],
        [''],
        $x5c,
        [...$x5c, 'garbage'],
        ['garbage', ...$x5c],
        [str_repeat('A', 100_000)],
        array_fill(0, 20, $x5c[0]),
        [$x5c[0], base64_encode(random_bytes(64))],
        [strtr($x5c[0], '+/', '-_')],
        [substr($x5c[0], 0, 40)],
    ];

    foreach ($corpora as $x5cInput) {
        try {
            Chain::fromX5c($x5cInput);
        } catch (CryptoException) {
            // The one permitted outcome.
        }
    }

    expect(true)->toBeTrue();
});

it('never leaks a native error from the codecs', function (): void {
    fuzzSink(fn (string $input): mixed => Base64Url::decode($input), Base64Url::encode('seed'));
    fuzzSink(fn (string $input): mixed => Base64::decode($input), Base64::encode('seed'));
    fuzzSink(fn (string $input): mixed => Base32::decode($input), Base32::encode('seed'));
    fuzzSink(fn (string $input): mixed => Hex::decode($input), Hex::encode('seed'));
});
