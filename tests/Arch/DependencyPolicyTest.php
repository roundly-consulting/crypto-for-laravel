<?php

declare(strict_types=1);

/**
 * The generic "only whitelisted runtime dependencies" loop that used to open this file is
 * gone: `ArchPresets::runtimeRequireIsWhitelisted()` in ArchTest.php asserts the same regex
 * against the same file, and is the fleet's single copy of the Dependency Policy.
 *
 * The two rules below are NOT generic and have no preset equivalent, so they stay. Both are
 * specific to crypto's contract with its consumers.
 */
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
