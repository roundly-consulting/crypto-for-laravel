<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Tests;

use Illuminate\Support\ServiceProvider;
use RoundlyConsulting\Crypto\CryptoServiceProvider;
use RoundlyConsulting\Testing\PackageTestCase;

abstract class TestCase extends PackageTestCase
{
    /**
     * Every provider crypto hard-requires, in registration order. A host auto-discovers
     * these; the suite must list them or the test environment is a fiction.
     *
     * @return list<class-string<ServiceProvider>>
     */
    protected function packageProviders(): array
    {
        return [CryptoServiceProvider::class];
    }

    /**
     * Crypto is zero-config and stateless: no config file, no migrations, no database. So
     * `migrationSources()` and `configBeforeBoot()` are deliberately left at the base
     * case's empty defaults rather than overridden — there is nothing to load and nothing
     * to pre-seed, and this package is the one that must never grow either.
     */
}
