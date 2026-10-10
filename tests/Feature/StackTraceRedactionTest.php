<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Codec\InvalidEncodingException;
use RoundlyConsulting\Crypto\CryptoManager;
use RoundlyConsulting\Crypto\Facades\Crypto;
use RoundlyConsulting\Crypto\Jose\MalformedTokenException;
use RoundlyConsulting\Crypto\Signature\InvalidSignatureException;
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
