<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Random\Bytes;
use RoundlyConsulting\Crypto\Random\Csprng;
use RoundlyConsulting\Crypto\Random\Secret;
use RoundlyConsulting\Crypto\Random\Token;
use RoundlyConsulting\Crypto\Signature\Ec\Der;
use RoundlyConsulting\Crypto\Signature\Ec\DerCodec;
use RoundlyConsulting\Crypto\Signature\Key\EcKey;
use RoundlyConsulting\Crypto\Signature\Key\EcKeys;
use RoundlyConsulting\Crypto\Signature\Key\Ed25519Keys;
use RoundlyConsulting\Crypto\Signature\Key\HmacSecret;
use RoundlyConsulting\Crypto\Signature\Key\HmacSecrets;
use RoundlyConsulting\Crypto\Signature\Key\OkpKey;
use RoundlyConsulting\Crypto\Signature\Key\RsaKey;
use RoundlyConsulting\Crypto\Signature\Key\RsaKeys;
use RoundlyConsulting\Crypto\X509\Certificate;
use RoundlyConsulting\Crypto\X509\Certificates;
use RoundlyConsulting\Crypto\X509\Chain;
use RoundlyConsulting\Crypto\X509\Chains;

/**
 * The facade's sub-accessors are pure delegation to the static factories. Two ways
 * that goes wrong silently, both pinned here:
 *
 *  1. DRIFT — a default, a type or a parameter name changes on the factory and not
 *     on the accessor, so `Crypto::keys()->rsa()->generate()` and `RsaKey::generate()`
 *     quietly disagree. Worse, a lost `#[SensitiveParameter]` on the accessor frame
 *     puts a private PEM into every stack trace that passes through it.
 *  2. GAPS — a new public factory lands on a key class and never reaches the facade.
 *
 * Every accessor method maps to exactly one factory, and every public factory of a
 * fronted class is mapped (the chain constructor counts: `fromCertificates()`).
 *
 * @return array<class-string, array{target: class-string, methods: array<string, string>}>
 */
function subAccessorMap(): array
{
    $same = static fn (string ...$names): array => array_combine($names, $names);

    return [
        RsaKeys::class => ['target' => RsaKey::class, 'methods' => $same(
            'public', 'private', 'fromModulusExponent', 'generate', 'publicFromStorage',
            'privateFromStorage', 'publicFromConfig', 'privateFromConfig', 'fromStorageOrGenerate',
        )],
        EcKeys::class => ['target' => EcKey::class, 'methods' => $same(
            'public', 'private', 'fromCoordinates', 'generate', 'publicFromStorage',
            'privateFromStorage', 'publicFromConfig', 'privateFromConfig', 'fromStorageOrGenerate',
        )],
        Ed25519Keys::class => ['target' => OkpKey::class, 'methods' => [
            'public' => 'ed25519',
            'private' => 'fromSecretKey',
            'generate' => 'generate',
            'publicFromStorage' => 'ed25519FromStorage',
            'privateFromStorage' => 'secretKeyFromStorage',
            'publicFromConfig' => 'ed25519FromConfig',
            'privateFromConfig' => 'secretKeyFromConfig',
            'fromStorageOrGenerate' => 'fromStorageOrGenerate',
        ]],
        HmacSecrets::class => ['target' => HmacSecret::class, 'methods' => $same(
            'fromString', 'generate', 'fromStorage', 'fromConfig', 'fromStorageOrGenerate',
        )],
        Certificates::class => ['target' => Certificate::class, 'methods' => $same(
            'fromPem', 'fromDer', 'fromBase64',
        )],
        Chains::class => ['target' => Chain::class, 'methods' => [
            'fromX5c' => 'fromX5c',
            'fromPems' => 'fromPems',
            'fromPemBundle' => 'fromPemBundle',
            'fromCertificates' => '__construct',
        ]],
        DerCodec::class => ['target' => Der::class, 'methods' => $same('fromRaw', 'toRaw', 'isValid')],
    ];
}

/**
 * @return list<array{name: string, type: string, default: mixed, sensitive: bool}>
 */
function parameterShape(ReflectionMethod $method): array
{
    return array_map(static fn (ReflectionParameter $parameter): array => [
        'name' => $parameter->getName(),
        'type' => (string) $parameter->getType(),
        'default' => $parameter->isDefaultValueAvailable() ? $parameter->getDefaultValue() : '(required)',
        'sensitive' => $parameter->getAttributes(SensitiveParameter::class) !== [],
    ], $method->getParameters());
}

/**
 * @return list<string>
 */
function publicMethodsDeclaredOn(string $class, bool $static): array
{
    $methods = array_filter(
        (new ReflectionClass($class))->getMethods(ReflectionMethod::IS_PUBLIC),
        static fn (ReflectionMethod $m): bool => $m->getDeclaringClass()->getName() === $class
            && $m->isStatic() === $static
            && ! str_starts_with($m->getName(), '__'),
    );

    $names = array_values(array_map(static fn (ReflectionMethod $m): string => $m->getName(), $methods));
    sort($names);

    return $names;
}

it('mirrors every factory signature exactly', function (string $accessor): void {
    ['target' => $target, 'methods' => $methods] = subAccessorMap()[$accessor];

    foreach ($methods as $method => $factory) {
        $mine = new ReflectionMethod($accessor, $method);
        $theirs = new ReflectionMethod($target, $factory);

        expect(parameterShape($mine))->toBe(parameterShape($theirs), "{$accessor}::{$method}() drifted from {$target}::{$factory}()");

        if ($factory !== '__construct') {
            $returns = (string) $theirs->getReturnType();

            expect((string) $mine->getReturnType())->toBe($returns === 'self' ? $target : $returns);
        }
    }
})->with(array_keys(subAccessorMap()));

it('exposes every public factory of the class it fronts, and nothing else', function (string $accessor): void {
    ['target' => $target, 'methods' => $methods] = subAccessorMap()[$accessor];

    $exposed = array_keys($methods);
    sort($exposed);

    $factories = array_values(array_filter($methods, static fn (string $m): bool => $m !== '__construct'));
    sort($factories);

    $accessorMethods = array_values(array_diff(publicMethodsDeclaredOn($accessor, static: false), ['chain']));

    expect($accessorMethods)->toBe($exposed)
        ->and(publicMethodsDeclaredOn($target, static: true))->toBe($factories);
})->with(array_keys(subAccessorMap()));

it('mirrors every CSPRNG helper', function (): void {
    $map = [
        'bytes' => [Bytes::class, 'generate'],
        'token' => [Token::class, 'urlSafe'],
        'numeric' => [Token::class, 'numeric'],
        'alphanumeric' => [Token::class, 'alphanumeric'],
        'fromAlphabet' => [Token::class, 'fromAlphabet'],
        'secret' => [Secret::class, 'base32'],
    ];

    foreach ($map as $method => [$class, $factory]) {
        $mine = new ReflectionMethod(Csprng::class, $method);
        $theirs = new ReflectionMethod($class, $factory);

        expect(parameterShape($mine))->toBe(parameterShape($theirs), "Csprng::{$method}() drifted from {$class}::{$factory}()")
            ->and((string) $mine->getReturnType())->toBe((string) $theirs->getReturnType());
    }

    $exposed = array_keys($map);
    sort($exposed);

    $factories = [
        ...publicMethodsDeclaredOn(Bytes::class, static: true),
        ...publicMethodsDeclaredOn(Token::class, static: true),
        ...publicMethodsDeclaredOn(Secret::class, static: true),
    ];
    sort($factories);

    $mapped = array_map(static fn (array $pair): string => $pair[1], array_values($map));
    sort($mapped);

    expect(publicMethodsDeclaredOn(Csprng::class, static: false))->toBe($exposed)
        ->and($factories)->toBe($mapped);
});

it('keeps secret inputs out of stack traces through the accessor frame', function (): void {
    foreach ([
        [RsaKeys::class, 'private'],
        [EcKeys::class, 'private'],
        [Ed25519Keys::class, 'private'],
        [HmacSecrets::class, 'fromString'],
    ] as [$class, $method]) {
        $parameter = (new ReflectionMethod($class, $method))->getParameters()[0];

        expect($parameter->getAttributes(SensitiveParameter::class))->not->toBe([], "{$class}::{$method}()");
    }
});
