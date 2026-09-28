<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use RoundlyConsulting\Crypto\Jose\ClaimMismatchException;
use RoundlyConsulting\Crypto\Jose\Claims;
use RoundlyConsulting\Crypto\Jose\TokenExpiredException;
use RoundlyConsulting\Crypto\Jose\TokenNotYetValidException;

afterEach(fn () => CarbonImmutable::setTestNow());

it('reads present and absent claims', function (): void {
    $claims = new Claims(['sub' => 'alice', 'n' => 3]);

    expect($claims->has('sub'))->toBeTrue()
        ->and($claims->has('missing'))->toBeFalse()
        ->and($claims->get('sub'))->toBe('alice')
        ->and($claims->get('missing'))->toBeNull()
        ->and($claims->require('sub'))->toBe('alice')
        ->and($claims->all())->toBe(['sub' => 'alice', 'n' => 3]);
});

it('reads typed claims', function (): void {
    $claims = new Claims(['s' => 'text', 'i' => 5, 'f' => 10.0, 'l' => ['a', 'b']]);

    expect($claims->string('s'))->toBe('text')
        ->and($claims->int('i'))->toBe(5)
        ->and($claims->int('f'))->toBe(10)
        ->and($claims->list('l'))->toBe(['a', 'b']);
});

it('throws on a missing required claim', function (): void {
    (new Claims([]))->require('x');
})->throws(ClaimMismatchException::class);

it('throws on a type mismatch', function (Closure $call): void {
    $call(new Claims(['s' => 1, 'i' => 'no', 'l' => 'no', 'f' => 1.5, 'lm' => [1, 2]]));
})->throws(ClaimMismatchException::class)->with([
    'string' => [fn (Claims $c) => $c->string('s')],
    'int' => [fn (Claims $c) => $c->int('i')],
    'fractional float as int' => [fn (Claims $c) => $c->int('f')],
    'list' => [fn (Claims $c) => $c->list('l')],
    'list of non-strings' => [fn (Claims $c) => $c->list('lm')],
]);

it('passes temporal validation for a live token', function (): void {
    CarbonImmutable::setTestNow(CarbonImmutable::createFromTimestamp(1_000));
    $claims = new Claims(['exp' => 2_000, 'nbf' => 500, 'iat' => 500]);

    $claims->assertTemporal();

    expect(true)->toBeTrue();
});

it('rejects an expired token', function (): void {
    CarbonImmutable::setTestNow(CarbonImmutable::createFromTimestamp(3_000));

    (new Claims(['exp' => 2_000]))->assertTemporal();
})->throws(TokenExpiredException::class);

it('accepts an expired token within leeway', function (): void {
    CarbonImmutable::setTestNow(CarbonImmutable::createFromTimestamp(2_005));

    (new Claims(['exp' => 2_000]))->assertTemporal(leeway: 30);

    expect(true)->toBeTrue();
});

it('rejects a not-yet-valid nbf', function (): void {
    CarbonImmutable::setTestNow(CarbonImmutable::createFromTimestamp(1_000));

    (new Claims(['exp' => 9_000, 'nbf' => 2_000]))->assertTemporal();
})->throws(TokenNotYetValidException::class);

it('rejects an iat in the future', function (): void {
    CarbonImmutable::setTestNow(CarbonImmutable::createFromTimestamp(1_000));

    (new Claims(['exp' => 9_000, 'iat' => 2_000]))->assertTemporal();
})->throws(TokenNotYetValidException::class);

it('requires exp for temporal validation', function (): void {
    (new Claims(['sub' => 'x']))->assertTemporal();
})->throws(ClaimMismatchException::class);

it('never wraps a whole float beyond the 64-bit range into an integer', function (float $value): void {
    // 1e19 would cast to -8446744073709551616 — a far-future nbf read as "long ago".
    (new Claims(['exp' => $value]))->int('exp');
})->throws(ClaimMismatchException::class, 'within the 64-bit integer range')->with([
    '1e19' => [1.0e19],
    '-1e19' => [-1.0e19],
    '2^63' => [9_223_372_036_854_775_808.0],
    'INF (a JSON 1e400)' => [INF],
    '-INF' => [-INF],
]);

it('refuses a far-future nbf rather than treating it as already valid', function (): void {
    CarbonImmutable::setTestNow(CarbonImmutable::createFromTimestamp(1_000));

    // Straight from the wire: a JSON number too big for an int decodes as a float.
    $claims = new Claims(json_decode('{"exp":2000,"nbf":10000000000000000000}', true));

    $claims->assertTemporal();
})->throws(ClaimMismatchException::class);

it('still reads whole floats at the edges of the 64-bit range', function (): void {
    $claims = new Claims(['max' => 4_611_686_018_427_387_904.0, 'min' => (float) PHP_INT_MIN]);

    expect($claims->int('max'))->toBe(4_611_686_018_427_387_904)
        ->and($claims->int('min'))->toBe(PHP_INT_MIN);
});
