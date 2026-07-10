<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Exceptions\CryptoException;
use RoundlyConsulting\Crypto\Signature\Algorithm;
use RoundlyConsulting\Crypto\Signature\Ec\Der;
use RoundlyConsulting\Crypto\Signature\EdDSA;
use RoundlyConsulting\Crypto\Signature\Es;
use RoundlyConsulting\Crypto\Signature\Key\EcKey;
use RoundlyConsulting\Crypto\Signature\Key\OkpKey;
use RoundlyConsulting\Crypto\Signature\Key\RsaKey;
use RoundlyConsulting\Crypto\Signature\Rs;

/*
 * Project Wycheproof (C2SP/wycheproof, testvectors_v1) parity.
 *
 * The committed JSON fixtures under tests/Fixtures/wycheproof/ are verbatim
 * copies of the upstream corpus (see tests/Fixtures/wycheproof/README.md for
 * provenance and the intentionally-skipped groups). Each test asserts our
 * verifier's accept/reject decision matches the vector's `result`:
 *   - `valid`      → we MUST accept
 *   - `invalid`    → we MUST reject
 *   - `acceptable` → lenient/legacy edge (e.g. ECDSA high-s malleability); we
 *                    pin no expectation and count it as skipped.
 */

/**
 * @return array{groups: list<array<string, mixed>>}
 */
function wycheproof(string $file): array
{
    /** @var array{testGroups: list<array<string, mixed>>} $data */
    $data = json_decode((string) file_get_contents(__DIR__.'/../Fixtures/wycheproof/'.$file), true, 512, JSON_THROW_ON_ERROR);

    return ['groups' => $data['testGroups']];
}

/**
 * Run a Wycheproof group set through a verify closure, asserting every
 * valid/invalid vector and skipping `acceptable` ones.
 *
 * @param  list<array<string, mixed>>  $groups
 * @param  callable(array<string, mixed>): (callable(array<string, mixed>): bool)  $verifierFor
 */
function assertWycheproof(array $groups, callable $verifierFor): void
{
    $failures = [];
    $checked = 0;
    $skipped = 0;

    foreach ($groups as $group) {
        $verify = $verifierFor($group);

        /** @var list<array{tcId: int, result: string, comment?: string}> $tests */
        $tests = $group['tests'];

        foreach ($tests as $test) {
            if ($test['result'] === 'acceptable') {
                $skipped++;

                continue;
            }

            $expected = $test['result'] === 'valid';
            $actual = $verify($test);
            $checked++;

            if ($actual !== $expected) {
                $failures[] = "tcId {$test['tcId']} ({$test['comment']}): expected ".($expected ? 'valid' : 'invalid').', got '.($actual ? 'valid' : 'invalid');
            }
        }
    }

    expect($failures)->toBe([])
        ->and($checked)->toBeGreaterThan(0);

    // Guard against a silent no-op run.
    test()->addToAssertionCount($skipped);
}

it('matches the Wycheproof ECDSA secp256r1/SHA-256 corpus', function (): void {
    assertWycheproof(wycheproof('ecdsa_secp256r1_sha256.json')['groups'], function (array $group): callable {
        /** @var string $pem */
        $pem = $group['publicKeyPem'];
        $verifier = new Es(EcKey::public($pem));

        return function (array $test) use ($verifier): bool {
            /** @var array{msg: string, sig: string} $test */
            try {
                $raw = Der::toRaw((string) hex2bin($test['sig']), 32);
            } catch (CryptoException) {
                return false;
            }

            return $verifier->verify((string) hex2bin($test['msg']), $raw);
        };
    });
});

it('matches the Wycheproof RSA PKCS1 2048/SHA-256 corpus', function (): void {
    assertWycheproof(wycheproof('rsa_signature_2048_sha256.json')['groups'], function (array $group): callable {
        /** @var string $pem */
        $pem = $group['publicKeyPem'];
        $verifier = new Rs(RsaKey::public($pem), Algorithm::RS256);

        return function (array $test) use ($verifier): bool {
            /** @var array{msg: string, sig: string} $test */
            try {
                return $verifier->verify((string) hex2bin($test['msg']), (string) hex2bin($test['sig']));
            } catch (CryptoException) {
                return false;
            }
        };
    });
});

it('matches the Wycheproof Ed25519 corpus', function (): void {
    assertWycheproof(wycheproof('ed25519.json')['groups'], function (array $group): callable {
        /** @var array{pk: string} $publicKey */
        $publicKey = $group['publicKey'];
        $verifier = new EdDSA(OkpKey::ed25519((string) hex2bin($publicKey['pk'])));

        return function (array $test) use ($verifier): bool {
            /** @var array{msg: string, sig: string} $test */
            try {
                return $verifier->verify((string) hex2bin($test['msg']), (string) hex2bin($test['sig']));
            } catch (CryptoException) {
                return false;
            }
        };
    });
})->skip(fn (): bool => ! function_exists('sodium_crypto_sign_verify_detached'), 'ext-sodium not loaded');
