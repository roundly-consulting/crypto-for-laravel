<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Hash\ConstantTime;

it('returns true for equal strings and false otherwise', function (): void {
    expect(ConstantTime::equals('abc', 'abc'))->toBeTrue()
        ->and(ConstantTime::equals('abc', 'abd'))->toBeFalse()
        ->and(ConstantTime::equals('abc', 'abcd'))->toBeFalse();
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
