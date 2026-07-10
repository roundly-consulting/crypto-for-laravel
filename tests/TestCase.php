<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Tests;

use Orchestra\Testbench\TestCase as Orchestra;
use RoundlyConsulting\Crypto\CryptoServiceProvider;

abstract class TestCase extends Orchestra
{
    /**
     * @return array<int, class-string>
     */
    protected function getPackageProviders($app): array
    {
        return [
            CryptoServiceProvider::class,
        ];
    }
}
