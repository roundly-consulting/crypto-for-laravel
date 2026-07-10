<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Hash\ConstantTime;

it('returns true for equal strings and false otherwise', function (): void {
    expect(ConstantTime::equals('abc', 'abc'))->toBeTrue()
        ->and(ConstantTime::equals('abc', 'abd'))->toBeFalse()
        ->and(ConstantTime::equals('abc', 'abcd'))->toBeFalse();
});
