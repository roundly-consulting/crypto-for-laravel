<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Signature\Key\EcKey;
use RoundlyConsulting\Crypto\Signature\Key\HmacSecret;
use RoundlyConsulting\Crypto\Signature\Key\OkpKey;
use RoundlyConsulting\Crypto\Signature\Key\RsaKey;

/**
 * The zero-config refinement (§1c): `env()` appears nowhere in the package, and
 * `config()` is called ONLY inside the whitelisted `*FromConfig` factory methods.
 *
 * This scans every `src/` file with the PHP tokenizer (so comments and strings
 * never trigger a false positive) and pins each `config(` call to an exact
 * method line range — a stricter, method-level guard than the class-level arch
 * test can express.
 *
 * @return list<array{name: string, line: int}>
 */
function scanCalls(string $file): array
{
    /** @var list<array{name: string, line: int}> $calls */
    $calls = [];
    $tokens = token_get_all((string) file_get_contents($file));
    $count = count($tokens);

    for ($i = 0; $i < $count; $i++) {
        $token = $tokens[$i];

        if (! is_array($token) || $token[0] !== T_STRING || ! in_array($token[1], ['config', 'env'], true)) {
            continue;
        }

        // The next meaningful token must be an opening paren (a call).
        $next = $i + 1;
        while (isset($tokens[$next]) && is_array($tokens[$next]) && $tokens[$next][0] === T_WHITESPACE) {
            $next++;
        }

        if (($tokens[$next] ?? null) !== '(') {
            continue;
        }

        // Skip method calls ($x->config(...) / Foo::config(...)).
        $prev = $i - 1;
        while ($prev >= 0 && is_array($tokens[$prev]) && $tokens[$prev][0] === T_WHITESPACE) {
            $prev--;
        }

        $before = $tokens[$prev] ?? null;
        if (is_array($before) && in_array($before[0], [T_OBJECT_OPERATOR, T_NULLSAFE_OBJECT_OPERATOR, T_DOUBLE_COLON], true)) {
            continue;
        }

        $calls[] = ['name' => $token[1], 'line' => $token[2]];
    }

    return $calls;
}

it('never calls env() anywhere in src', function (): void {
    $files = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator(realpath(__DIR__.'/../../src'), FilesystemIterator::SKIP_DOTS),
    );

    foreach ($files as $file) {
        if ($file->getExtension() !== 'php') {
            continue;
        }

        $env = array_filter(scanCalls($file->getPathname()), fn (array $c): bool => $c['name'] === 'env');

        expect($env)->toBe([], "env() called in {$file->getPathname()}");
    }
});

it('calls config() only inside the whitelisted *FromConfig factories', function (): void {
    $whitelist = [
        HmacSecret::class => ['fromConfig'],
        RsaKey::class => ['publicFromConfig', 'privateFromConfig'],
        EcKey::class => ['publicFromConfig', 'privateFromConfig'],
        OkpKey::class => ['ed25519FromConfig', 'secretKeyFromConfig'],
    ];

    // file path => list of [startLine, endLine] ranges where config() is allowed.
    $allowedRanges = [];
    foreach ($whitelist as $class => $methods) {
        $reflection = new ReflectionClass($class);
        $file = (string) $reflection->getFileName();

        foreach ($methods as $method) {
            $reflectionMethod = new ReflectionMethod($class, $method);
            $allowedRanges[$file][] = [$reflectionMethod->getStartLine(), $reflectionMethod->getEndLine()];
        }
    }

    $files = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator(realpath(__DIR__.'/../../src'), FilesystemIterator::SKIP_DOTS),
    );

    $seen = 0;

    foreach ($files as $file) {
        if ($file->getExtension() !== 'php') {
            continue;
        }

        $path = $file->getPathname();

        foreach (scanCalls($path) as $call) {
            if ($call['name'] !== 'config') {
                continue;
            }

            $ranges = $allowedRanges[$path] ?? [];
            $inRange = false;
            foreach ($ranges as [$start, $end]) {
                if ($call['line'] >= $start && $call['line'] <= $end) {
                    $inRange = true;
                    break;
                }
            }

            expect($inRange)->toBeTrue("config() called outside a *FromConfig factory at {$path}:{$call['line']}");
            $seen++;
        }
    }

    // Sanity: the seven fromConfig factories really do read config (guards
    // against a scan that silently matches nothing).
    expect($seen)->toBe(7);
});
