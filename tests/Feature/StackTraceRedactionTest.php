<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Codec\Base64Url;
use RoundlyConsulting\Crypto\Codec\InvalidEncodingException;
use RoundlyConsulting\Crypto\CryptoManager;
use RoundlyConsulting\Crypto\Exceptions\CryptoException;
use RoundlyConsulting\Crypto\Facades\Crypto;
use RoundlyConsulting\Crypto\Jose\FlattenedJws;
use RoundlyConsulting\Crypto\Jose\Jwk;
use RoundlyConsulting\Crypto\Jose\MalformedJwkException;
use RoundlyConsulting\Crypto\Jose\MalformedTokenException;
use RoundlyConsulting\Crypto\Signature\Algorithm;
use RoundlyConsulting\Crypto\Signature\Es;
use RoundlyConsulting\Crypto\Signature\InvalidSignatureException;
use RoundlyConsulting\Crypto\Signature\Key\EcKey;
use RoundlyConsulting\Crypto\Signature\Key\OkpKey;
use RoundlyConsulting\Crypto\Signature\Key\RsaKey;
use RoundlyConsulting\Crypto\Signature\KeyLoadException;
use RoundlyConsulting\Crypto\Signature\KeyVerifier;
use RoundlyConsulting\Crypto\Signature\OpenSsl;
use RoundlyConsulting\Crypto\Signature\Rs;
use RoundlyConsulting\Crypto\Signature\WeakKeyException;
use RoundlyConsulting\Crypto\Testing\TestKeys;

/**
 * End to end: a secret handed to the package must not reach a stack trace through any frame
 * the package owns on the way down, codecs and private helpers included. The reflection pin
 * in tests/Arch/SensitiveParameterTest.php lists the marked parameters; this proves the marks
 * hold on the paths an exception really takes.
 *
 * Most flat calls go through the injected manager here; the last case runs the same secrets
 * through the facade, whose `__callStatic()` frame would otherwise record them raw (the facade
 * uses the toolkit's `RedactsSensitiveArguments`; FacadeTest pins its count).
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

/**
 * The same secrets through the facade's flat shortcuts. Laravel's stock `__callStatic()` frame
 * holds every forwarded argument raw; the redacting facade replaces each one the manager marks
 * with a `SensitiveParameterValue` before it forwards.
 */
dataset('flat facade calls handed a secret', function (): array {
    $rsaPem = keyPem('rsa-private');
    $rsaLine = explode("\n", $rsaPem)[3];
    $rsaDer = (string) base64_decode((string) preg_replace('/-----[A-Z ]+-----|\s+/', '', $rsaPem), true);
    $privateJwk = '{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","d":"jpsQnnGQmL-YBIffH1136cLDTpBWRMiCIqqqM4xsAhQ"}';

    return [
        'Crypto::certificate() given a private key' => [fn (): array => [fn (): mixed => Crypto::certificate($rsaPem), $rsaLine]],
        'Crypto::chainFromPemBundle() given a key-only bundle' => [fn (): array => [fn (): mixed => Crypto::chainFromPemBundle($rsaPem), $rsaLine]],
        'Crypto::chainFromX5c() given a private key' => [fn (): array => [fn (): mixed => Crypto::chainFromX5c([base64_encode($rsaDer)]), $rsaLine]],
        'Crypto::jwkFromJson() given a private JWK' => [fn (): array => [fn (): mixed => Crypto::jwkFromJson($privateJwk), 'jpsQnnGQmL-YBIffH1136cLDTpBWRMiCIqqqM4xsAhQ']],
        'Crypto::jwkFromArray() given a symmetric JWK' => [fn (): array => [fn (): mixed => Crypto::jwkFromArray(['kty' => 'oct', 'k' => 'GawgguFyGrWKav7AX4VKUg-shared-secret']), 'GawgguFyGrWKav7AX4VKUg-shared-secret']],
        'Crypto::constantTimeEquals() given a non-string' => [fn (): array => [fn (): mixed => Crypto::constantTimeEquals('known-mac-value', []), 'known-mac-value']],
        'Crypto::provisioningUri() given a spaced secret' => [fn (): array => [fn (): mixed => Crypto::provisioningUri('JBSW Y3DP EHPK 3PXP', 'ada@example.com', 'Example'), 'Y3DP']],
        'Crypto::base64Decode() given a malformed key' => [fn (): array => [fn (): mixed => Crypto::base64Decode('c2VjcmV0LWtleS1tYXRlcmlhbA=!'), 'c2VjcmV0LWtleS1tYXRlcmlhbA']],
    ];
});

it('keeps a secret passed through a flat facade call out of the trace', function (Closure $case): void {
    $needles = $case();
    $call = array_shift($needles);

    $error = thrownBy($call);

    expect($error)->toBeInstanceOf(Throwable::class);

    foreach ($needles as $needle) {
        expect(framesLeaking($error, $needle))->toBe([]);
    }

    expect(redactedArguments($error))->toBeGreaterThan(0);
})->with('flat facade calls handed a secret');

/**
 * A signature is half a credential: every JWS verification frame also holds the signing input
 * (`header.payload`), and the two rebuild the bearer token. So no frame the signature passes
 * through on its way down may record it, verifiers and the DER ↔ raw codec included.
 *
 * The keys below are built past their own factories so the verifier throws INSIDE `verify()`,
 * with the signature on the stack: each claims to be private, so the verifier derives its public
 * half, and that half is refused (a 1024-bit RSA key; an RSA handle posing as an EC key).
 */
function rsaKeyThatThrowsInsideVerify(): RsaKey
{
    $reflection = new ReflectionClass(RsaKey::class);
    $key = $reflection->newInstanceWithoutConstructor();
    $reflection->getMethod('__construct')->invoke($key, openssl_pkey_get_public(keyPem('weak-1024-public')), true);

    return $key;
}

function ecKeyThatThrowsInsideVerify(): EcKey
{
    $reflection = new ReflectionClass(EcKey::class);
    $key = $reflection->newInstanceWithoutConstructor();
    $reflection->getMethod('__construct')->invoke($key, openssl_pkey_get_public(keyPem('rsa-public')), true, 'P-256');

    return $key;
}

/**
 * The frame names from {@see framesLeaking()}, without their position in the trace.
 *
 * @param  list<string>  $frames
 * @return list<string>
 */
function frameNames(array $frames): array
{
    return array_map(static fn (string $frame): string => (string) preg_replace('/#\d+$/', '', $frame), $frames);
}

it('keeps an RS256 signature out of the trace when the verifier throws inside verify', function (): void {
    $token = Crypto::jws()->sign([], ['sub' => 'ada'], Crypto::rs(Crypto::keys()->rsa()->private(keyPem('rsa-private'))));
    [$header, $payload, $signature] = explode('.', $token);
    $verifier = Crypto::rs(rsaKeyThatThrowsInsideVerify());

    $error = thrownBy(fn (): mixed => Crypto::jws()->verify($token, $verifier, Algorithm::RS256));

    expect($error)->toBeInstanceOf(WeakKeyException::class)
        ->and(framesLeaking($error, Base64Url::decode($signature)))->toBe([])
        ->and(framesLeaking($error, $signature))->toBe([])
        ->and(framesLeaking($error, $token))->toBe([])
        // The signing input alone is no credential and stays visible: proof that the trace
        // records arguments, and that the throw came from inside the verifier's frame.
        ->and(frameNames(framesLeaking($error, $header.'.'.$payload)))->toContain(Rs::class.'->verify');
});

it('keeps an ES256 signature out of the trace when the verifier throws inside verify', function (): void {
    $token = Crypto::jws()->sign([], ['sub' => 'ada'], Crypto::es(Crypto::keys()->ec()->private(keyPem('ec-private'))));
    [$header, $payload, $signature] = explode('.', $token);
    $verifier = Crypto::es(ecKeyThatThrowsInsideVerify());

    $error = thrownBy(fn (): mixed => Crypto::jws()->verify($token, $verifier, Algorithm::ES256));

    expect($error)->toBeInstanceOf(KeyLoadException::class)
        ->and(framesLeaking($error, Base64Url::decode($signature)))->toBe([])
        ->and(framesLeaking($error, $token))->toBe([])
        ->and(frameNames(framesLeaking($error, $header.'.'.$payload)))->toContain(Es::class.'->verify');
});

it('keeps a DER signature out of the trace when the key verifier throws inside verify', function (): void {
    $message = 'authenticator-data-and-client-data-hash';
    $raw = Crypto::es(Crypto::keys()->ec()->private(keyPem('ec-private')))->sign($message);
    $der = Crypto::ecDer()->fromRaw($raw);

    $error = thrownBy(fn (): bool => Crypto::verifier()->verify(ecKeyThatThrowsInsideVerify(), $message, $der));

    expect($error)->toBeInstanceOf(KeyLoadException::class)
        ->and(framesLeaking($error, $der))->toBe([])
        ->and(framesLeaking($error, $raw))->toBe([])
        ->and(frameNames(framesLeaking($error, $message)))->toContain(KeyVerifier::class.'->verify', Es::class.'->verify');
});

it('keeps an ECDSA signature out of the trace when the codec refuses it', function (Closure $case): void {
    [$convert, $needle] = $case();

    $error = thrownBy($convert);

    expect($error)->toBeInstanceOf(InvalidSignatureException::class)
        ->and(framesLeaking($error, $needle))->toBe([])
        ->and(redactedArguments($error))->toBeGreaterThanOrEqual(2);
})->with([
    'a raw P-256 signature read at the P-384 size' => [function (): array {
        $raw = Crypto::es(Crypto::keys()->ec()->private(keyPem('ec-private')))->sign('message');

        return [fn (): string => Crypto::ecDer()->fromRaw($raw, 48), $raw];
    }],
    'a DER P-384 signature read at the P-256 size' => [function (): array {
        $der = Crypto::ecDer()->fromRaw(Crypto::es(TestKeys::ec('P-384'))->sign('message'), 48);

        return [fn (): string => Crypto::ecDer()->toRaw($der, 32), $der];
    }],
]);

/**
 * Every package frame that takes a whole signature, made to throw on a different argument, so
 * the frame is on the stack with the signature in it.
 */
dataset('frames handed a signature', function (): array {
    $signature = 'c2lnbmF0dXJlLWJ5dGVzLXRoYXQtbXVzdC1ub3QtbGVhaw';
    $rsa = static fn (): RsaKey => RsaKey::public(keyPem('rsa-public'));
    $ec = static fn (): EcKey => EcKey::public(keyPem('ec-public'));

    return [
        'Hs::verify()' => [fn (): array => [fn (): mixed => Crypto::hs(TestKeys::hmacSecret())->verify(null, $signature), $signature]],
        'Rs::verify()' => [fn (): array => [fn (): mixed => Crypto::rs($rsa())->verify(null, $signature), $signature]],
        'Es::verify()' => [fn (): array => [fn (): mixed => Crypto::es($ec())->verify(null, $signature), $signature]],
        'EdDSA::verify()' => [fn (): array => [fn (): mixed => Crypto::eddsa(OkpKey::ed25519(str_repeat("\x01", 32)))->verify(null, $signature), $signature]],
        'KeyVerifier::verify()' => [fn (): array => [fn (): mixed => Crypto::verifier()->verify($rsa(), null, $signature), $signature]],
        'OpenSsl::verify()' => [fn (): array => [fn (): mixed => OpenSsl::verify('message', $signature, null, OPENSSL_ALGO_SHA256), $signature]],
        'DerCodec::fromRaw()' => [fn (): array => [fn (): mixed => Crypto::ecDer()->fromRaw($signature, null), $signature]],
        'DerCodec::toRaw()' => [fn (): array => [fn (): mixed => Crypto::ecDer()->toRaw($signature, null), $signature]],
        'FlattenedJws::__construct()' => [fn (): array => [fn (): mixed => new FlattenedJws('protected', null, $signature), $signature]],
    ];
});

it('keeps a signature out of the frame of every verifier and codec', function (Closure $case): void {
    [$call, $needle] = $case();

    $error = thrownBy($call);

    expect($error)->toBeInstanceOf(TypeError::class)
        ->and(framesLeaking($error, $needle))->toBe([])
        ->and(redactedArguments($error))->toBeGreaterThan(0);
})->with('frames handed a signature');
