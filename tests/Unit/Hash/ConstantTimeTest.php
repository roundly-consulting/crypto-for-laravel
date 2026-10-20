<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\CryptoManager;
use RoundlyConsulting\Crypto\Facades\Crypto;
use RoundlyConsulting\Crypto\Hash\ConstantTime;

it('returns true for equal strings and false otherwise', function (): void {
    expect(ConstantTime::equals('abc', 'abc'))->toBeTrue()
        ->and(ConstantTime::equals('abc', 'abd'))->toBeFalse()
        ->and(ConstantTime::equals('abc', 'abcd'))->toBeFalse();
});

it('never matches an empty known value', function (string $via): void {
    // A blank known value is a missing secret (`env('WEBHOOK_SECRET', '')`). An empty
    // submission, or `false` from a non-strict host, used to satisfy it.
    $compare = static fn (string $known, string $user): bool => match ($via) {
        'ConstantTime::equals' => ConstantTime::equals($known, $user),
        'CryptoManager::constantTimeEquals' => app(CryptoManager::class)->constantTimeEquals($known, $user),
        'Crypto::constantTimeEquals' => Crypto::constantTimeEquals($known, $user),
    };

    expect($compare('', ''))->toBeFalse()
        ->and($compare('', 'x'))->toBeFalse()
        ->and($compare('x', 'x'))->toBeTrue();
})->with(['ConstantTime::equals', 'CryptoManager::constantTimeEquals', 'Crypto::constantTimeEquals']);

it('never matches an empty known value against false from a non-strict caller', function (): void {
    // A host without strict_types coerces `false` to `''`. The facade forwards from a
    // non-strict frame, and an internal function such as array_map() calls back in
    // coercive mode, so both reproduce that host from this strict file.
    expect(Crypto::constantTimeEquals('', false))->toBeFalse()
        ->and(array_map(ConstantTime::equals(...), [''], [false]))->toBe([false])
        ->and(array_map(app(CryptoManager::class)->constantTimeEquals(...), [''], [false]))->toBe([false]);
});

it('keeps both inputs out of stack traces', function (): void {
    $previous = ini_set('zend.exception_ignore_args', '0');

    try {
        // A TypeError raised on entry still records the frame with every argument
        // passed, so a wrong-typed partner puts the other input on the trace.
        foreach ([['the-known-secret', 42], [42, 'the-user-secret']] as $arguments) {
            try {
                ConstantTime::equals(...$arguments);
                $this->fail('equals() accepted a non-string input.');
            } catch (TypeError $error) {
                $frame = $error->getTrace()[0];

                expect($frame['class'] ?? null)->toBe(ConstantTime::class)
                    ->and($frame['function'])->toBe('equals')
                    ->and($frame['args'] ?? [])->toHaveCount(2)
                    ->each->toBeInstanceOf(SensitiveParameterValue::class);
            }
        }
    } finally {
        ini_set('zend.exception_ignore_args', (string) $previous);
    }
});
