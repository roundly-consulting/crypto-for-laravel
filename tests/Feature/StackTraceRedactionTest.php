<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Codec\InvalidEncodingException;
use RoundlyConsulting\Crypto\CryptoManager;
use RoundlyConsulting\Crypto\Exceptions\CryptoException;
use RoundlyConsulting\Crypto\Facades\Crypto;
use RoundlyConsulting\Crypto\Jose\Jwk;
use RoundlyConsulting\Crypto\Jose\MalformedJwkException;
use RoundlyConsulting\Crypto\Jose\MalformedTokenException;
use RoundlyConsulting\Crypto\Signature\InvalidSignatureException;
use RoundlyConsulting\Crypto\Signature\Key\RsaKey;
use RoundlyConsulting\Crypto\Signature\KeyLoadException;
use RoundlyConsulting\Crypto\Testing\TestKeys;

/**
 * End to end: a secret handed to the package must not reach a stack trace through any frame
 * the package owns on the way down, codecs and private helpers included. The reflection pin
 * in tests/Arch/SensitiveParameterTest.php lists the marked parameters; this proves the marks
 * hold on the paths an exception really takes.
 *
 * Flat calls that take a secret go through the injected manager here, not the facade:
 * Laravel's own `Facade::__callStatic()` frame records the arguments it forwards, and that
 * frame is not the package's to mark (see the technical docs, security notes).
 */
beforeEach(function (): void {
    // Production php.ini drops arguments from traces entirely, which would make every
    // assertion below pass over nothing. Record them, as development setups and error
    // reporters do.
    $this->ignoreArgs = ini_set('zend.exception_ignore_args', '0');
});

afterEach(function (): void {
    ini_set('zend.exception_ignore_args', (string) $this->ignoreArgs);
});

/**
 * Every place in the trace where the needle appears in plain text, as `function#index`.
 * Objects are not walked (reporters reduce them to a class name); arrays are.
 *
 * @return list<string>
 */
function framesLeaking(Throwable $exception, string $needle): array
{
    $contains = static function (mixed $value) use (&$contains, $needle): bool {
        return match (true) {
            is_string($value) => str_contains($value, $needle),
            is_array($value) => array_filter($value, $contains) !== [],
            default => false,
        };
    };

    $leaks = [];

    foreach ($exception->getTrace() as $index => $frame) {
        if ($contains($frame['args'] ?? [])) {
            $leaks[] = ($frame['class'] ?? '').($frame['type'] ?? '').$frame['function'].'#'.$index;
        }
    }

    return $leaks;
}

/**
 * How many arguments in the trace were redacted. A non-zero count proves the trace carried
 * arguments at all, so an empty leak list means something.
 */
function redactedArguments(Throwable $exception): int
{
    $count = 0;

    foreach ($exception->getTrace() as $frame) {
        foreach ($frame['args'] ?? [] as $argument) {
            $count += $argument instanceof SensitiveParameterValue ? 1 : 0;
        }
    }

    return $count;
}

/**
 * Run the callback and return what it threw.
 */
function thrownBy(Closure $callback): Throwable
{
    try {
        $callback();
    } catch (Throwable $thrown) {
        return $thrown;
    }

    throw new LogicException('The callback did not throw.');
}

it('keeps the known value out of the trace of a constant-time compare', function (): void {
    $error = thrownBy(fn (): bool => app(CryptoManager::class)->constantTimeEquals('known-mac-value', 42));

    expect($error)->toBeInstanceOf(TypeError::class)
        ->and(framesLeaking($error, 'known-mac-value'))->toBe([])
        ->and(redactedArguments($error))->toBeGreaterThan(0);
});

it('keeps an otp secret out of the trace when it fails to decode', function (): void {
    // Authenticator apps display secrets in groups; a host that forgets to strip the
    // spaces gets an encoding error, and that error must not carry the secret.
    $secret = 'JBSW Y3DP EHPK 3PXP JBSW Y3DP EHPK 3PXP';

    $error = thrownBy(fn (): int|false => Crypto::totp()->verify($secret, '123456'));

    expect($error)->toBeInstanceOf(InvalidEncodingException::class)
        ->and(framesLeaking($error, 'Y3DP'))->toBe([])
        ->and(redactedArguments($error))->toBeGreaterThanOrEqual(4);
});

it('keeps an otp secret out of the trace of a provisioning uri', function (): void {
    $error = thrownBy(fn (): string => app(CryptoManager::class)->provisioningUri('JBSW Y3DP EHPK 3PXP', 'ada@example.com', 'Example'));

    expect($error)->toBeInstanceOf(InvalidEncodingException::class)
        ->and(framesLeaking($error, 'Y3DP'))->toBe([]);
});

it('keeps a malformed base64 key out of the trace of a codec', function (): void {
    $error = thrownBy(fn (): string => app(CryptoManager::class)->base64Decode('c2VjcmV0LWtleS1tYXRlcmlhbA=!'));

    expect($error)->toBeInstanceOf(InvalidEncodingException::class)
        ->and(framesLeaking($error, 'c2VjcmV0LWtleS1tYXRlcmlhbA'))->toBe([]);
});

it('keeps a bearer token out of the trace when it fails to verify', function (): void {
    $signer = Crypto::hs(TestKeys::hmacSecret());
    $token = Crypto::jws()->sign(['alg' => 'HS256'], ['sub' => 'ada'], Crypto::hs(Crypto::generateHmacSecret()));

    $error = thrownBy(fn (): mixed => Crypto::jws()->verify($token, $signer, $signer->algorithm()));

    expect($error)->toBeInstanceOf(InvalidSignatureException::class)
        ->and(framesLeaking($error, explode('.', $token)[2]))->toBe([])
        ->and(framesLeaking($error, $token))->toBe([]);
});

it('keeps a malformed bearer token out of the trace', function (): void {
    $token = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZGEifQ';
    $signer = Crypto::hs(TestKeys::hmacSecret());

    $error = thrownBy(fn (): mixed => Crypto::jws()->verify($token, $signer, $signer->algorithm()));

    expect($error)->toBeInstanceOf(MalformedTokenException::class)
        ->and(framesLeaking($error, 'eyJzdWIiOiJhZGEifQ'))->toBe([]);
});

/**
 * A private key handed to a PUBLIC loader by mistake: the wrong file, a key-only bundle, a
 * private JWK. Each loader refuses it, and the refusal must not carry the key. The body line
 * is a slice of the key's base64 body, so it also matches the PEM a DER loader builds; a DER
 * case also looks for a slice of the raw bytes.
 *
 * Each case is a closure returning [the call, ...the needles], so the needle never becomes an
 * argument of the test's own frames, which would leak it into the trace on the test's side.
 */
dataset('public loaders handed a private key', function (): array {
    $rsaPem = keyPem('rsa-private');
    $ecPem = keyPem('ec-private');
    $rsaLine = explode("\n", $rsaPem)[3];
    $ecLine = explode("\n", $ecPem)[1];
    $rsaDer = (string) base64_decode((string) preg_replace('/-----[A-Z ]+-----|\s+/', '', $rsaPem), true);
    $garbled = str_replace('A', '*', $rsaPem);
    $crypto = static fn (): CryptoManager => app(CryptoManager::class);

    return [
        'RsaKey::public() given an EC private key' => [fn (): array => [fn (): mixed => $crypto()->keys()->rsa()->public($ecPem), $ecLine]],
        'EcKey::public() given an RSA private key' => [fn (): array => [fn (): mixed => $crypto()->keys()->ec()->public($rsaPem), $rsaLine]],
        'RsaKey::public() given a garbled private key' => [fn (): array => [fn (): mixed => RsaKey::public($garbled), explode("\n", $garbled)[3]]],
        'Certificate::fromPem() given a private key' => [fn (): array => [fn (): mixed => $crypto()->certificate($rsaPem), $rsaLine]],
        'Certificate::fromDer() given a private key' => [fn (): array => [fn (): mixed => $crypto()->x509()->fromDer($rsaDer), $rsaLine, substr($rsaDer, 96, 48)]],
        'Certificate::fromBase64() given a private key' => [fn (): array => [fn (): mixed => $crypto()->x509()->fromBase64(base64_encode($rsaDer)), $rsaLine]],
        'Chain::fromPemBundle() given a key-only bundle' => [fn (): array => [fn (): mixed => $crypto()->chainFromPemBundle($rsaPem), $rsaLine]],
        'Chain::fromPems() given a private key' => [fn (): array => [fn (): mixed => $crypto()->x509()->chain()->fromPems([$rsaPem]), $rsaLine]],
        'Chain::fromPems() given a key beside a non-string' => [fn (): array => [fn (): mixed => $crypto()->x509()->chain()->fromPems([$rsaPem, 42]), $rsaLine]],
        'Chain::fromX5c() given a private key' => [fn (): array => [fn (): mixed => $crypto()->chainFromX5c([base64_encode($rsaDer)]), $rsaLine]],
    ];
});

it('keeps a private key handed to a public loader out of the trace', function (Closure $case): void {
    $needles = $case();
    $load = array_shift($needles);

    $error = thrownBy($load);

    expect($error)->toBeInstanceOf(CryptoException::class);

    foreach ($needles as $needle) {
        expect(framesLeaking($error, $needle))->toBe([]);
    }

    expect(redactedArguments($error))->toBeGreaterThan(0);
})->with('public loaders handed a private key');

it('keeps an ed25519 secret key handed to the public loader out of the trace', function (): void {
    $keypair = sodium_crypto_sign_keypair();
    $secretKey = sodium_crypto_sign_secretkey($keypair);
    $seed = substr($secretKey, 0, 32);

    $error = thrownBy(fn (): mixed => app(CryptoManager::class)->keys()->ed25519()->public($secretKey));

    expect($error)->toBeInstanceOf(KeyLoadException::class)
        ->and(framesLeaking($error, $seed))->toBe([])
        ->and(redactedArguments($error))->toBeGreaterThanOrEqual(2);
})->skip(fn (): bool => ! function_exists('sodium_crypto_sign_keypair'), 'ext-sodium not loaded');

it('keeps a private jwk out of the trace when it is refused', function (Closure $case): void {
    [$parse, $secret] = $case();

    $error = thrownBy($parse);

    expect($error)->toBeInstanceOf(MalformedJwkException::class)
        ->and(framesLeaking($error, $secret))->toBe([])
        ->and(redactedArguments($error))->toBeGreaterThanOrEqual(2);
})->with([
    'a private EC JWK as JSON' => [fn (): array => [
        fn (): mixed => app(CryptoManager::class)->jwkFromJson('{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","d":"jpsQnnGQmL-YBIffH1136cLDTpBWRMiCIqqqM4xsAhQ"}'),
        'jpsQnnGQmL-YBIffH1136cLDTpBWRMiCIqqqM4xsAhQ',
    ]],
    'a symmetric JWK' => [fn (): array => [
        fn (): mixed => app(CryptoManager::class)->jwkFromArray(['kty' => 'oct', 'k' => 'GawgguFyGrWKav7AX4VKUg-shared-secret']),
        'GawgguFyGrWKav7AX4VKUg-shared-secret',
    ]],
    'a private RSA JWK with an oversized member' => [fn (): array => [
        fn (): mixed => Jwk::fromArray(['kty' => 'RSA', 'n' => str_repeat('A', Jwk::MAX_MEMBER_BYTES + 1), 'e' => 'AQAB', 'd' => 'X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9']),
        'X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9',
    ]],
]);
