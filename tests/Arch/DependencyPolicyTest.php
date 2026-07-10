<?php

declare(strict_types=1);

it('only requires whitelisted runtime dependencies', function (): void {
    /** @var array{require?: array<string, string>} $composer */
    $composer = json_decode((string) file_get_contents(__DIR__.'/../../composer.json'), true, 512, JSON_THROW_ON_ERROR);
    $require = $composer['require'] ?? [];

    foreach (array_keys($require) as $package) {
        expect((bool) preg_match('#^(php$|ext-|illuminate/|laravel/|symfony/|roundly-consulting/)#', $package))
            ->toBeTrue("Disallowed runtime dependency: {$package}");
    }
});

it('declares ext-sodium as a suggestion, never a hard requirement', function (): void {
    /** @var array{require?: array<string, string>, suggest?: array<string, string>} $composer */
    $composer = json_decode((string) file_get_contents(__DIR__.'/../../composer.json'), true, 512, JSON_THROW_ON_ERROR);

    expect($composer['require'] ?? [])->not->toHaveKey('ext-sodium')
        ->and($composer['suggest'] ?? [])->toHaveKey('ext-sodium');
});

it('keeps supporting the latest two Laravel majors', function (): void {
    /** @var array{require?: array<string, string>} $composer */
    $composer = json_decode((string) file_get_contents(__DIR__.'/../../composer.json'), true, 512, JSON_THROW_ON_ERROR);

    expect($composer['require']['illuminate/contracts'] ?? '')->toBe('^12.0|^13.0');
});
