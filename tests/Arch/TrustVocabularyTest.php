<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\X509\Certificate;
use RoundlyConsulting\Crypto\X509\Chain;
use RoundlyConsulting\Crypto\X509\DistinguishedName;
use RoundlyConsulting\Crypto\X509\OpenSslX509;

/**
 * The hard boundary, made machine-checkable: **crypto owns algorithms, the
 * consumer owns trust.**
 *
 * `Crypto\X509` answers "is this certificate signed by that one" and "what is its
 * fingerprint". It must never answer "do I trust it". So no public method of the
 * module may be named for a trust decision — no `isTrusted()`, no `pin()`, no
 * `checkPurpose()`, no `matchesHostname()`, no revocation, no `verify()`. A PR
 * that adds one fails here instead of relying on a reviewer's eye.
 *
 * `Chain` additionally may not use the word "valid" at all: `isLinked()` proves
 * the math and blesses nothing. Only `Certificate`'s three RFC 5280
 * validity-PERIOD predicates may say "valid", and they are dates, not trust.
 */
it('never speaks the vocabulary of trust in the X509 module', function (string $class): void {
    $banned = '/trust|pin|anchor|revoc|purpose|hostname|verify/i';

    foreach ((new ReflectionClass($class))->getMethods(ReflectionMethod::IS_PUBLIC) as $method) {
        expect(preg_match($banned, $method->getName()))
            ->toBe(0, "{$class}::{$method->getName()}() reads as a trust decision; crypto does not make those");
    }
})->with([
    Certificate::class,
    Chain::class,
    DistinguishedName::class,
    OpenSslX509::class,
]);

it('never calls a chain valid', function (): void {
    foreach ((new ReflectionClass(Chain::class))->getMethods(ReflectionMethod::IS_PUBLIC) as $method) {
        expect(preg_match('/valid/i', $method->getName()))
            ->toBe(0, "Chain::{$method->getName()}() implies a ruling the chain cannot make");
    }
});

it('confines the validity vocabulary to the certificate date predicates', function (): void {
    $valid = array_values(array_filter(
        array_map(
            static fn (ReflectionMethod $method): string => $method->getName(),
            (new ReflectionClass(Certificate::class))->getMethods(ReflectionMethod::IS_PUBLIC),
        ),
        static fn (string $name): bool => preg_match('/valid/i', $name) === 1,
    ));

    sort($valid);

    expect($valid)->toBe(['isNotYetValidAt', 'isValidAt']);
});

it('keeps the OpenSSL X509 gateway internal', function (): void {
    $docblock = (string) (new ReflectionClass(OpenSslX509::class))->getDocComment();

    expect($docblock)->toContain('@internal');
});
