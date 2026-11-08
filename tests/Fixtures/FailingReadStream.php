<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Tests\Fixtures;

/**
 * A user-space stream wrapper whose second read fails before the end of the data, the way a
 * dropped network stream or a vanished file does. `feof()` stays false, so a digest that
 * stopped early cannot pass for the digest of the whole stream.
 */
final class FailingReadStream
{
    public const string SCHEME = 'crypto-failing';

    /** @var resource|null */
    public $context;

    private int $reads = 0;

    public static function register(): void
    {
        if (! in_array(self::SCHEME, stream_get_wrappers(), true)) {
            stream_wrapper_register(self::SCHEME, self::class);
        }
    }

    public function stream_open(string $path, string $mode, int $options, ?string &$openedPath): bool
    {
        return true;
    }

    public function stream_read(int $count): string|false
    {
        return $this->reads++ === 0 ? 'partial' : false;
    }

    public function stream_eof(): bool
    {
        return false;
    }

    /**
     * @return array<int|string, int>|false
     */
    public function url_stat(string $path, int $flags): array|false
    {
        return false;
    }
}
