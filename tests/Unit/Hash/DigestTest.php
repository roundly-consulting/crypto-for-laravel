<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Exceptions\CryptoException;
use RoundlyConsulting\Crypto\Hash\Digest;
use RoundlyConsulting\Crypto\Hash\HashAlgorithm;
use RoundlyConsulting\Crypto\Hash\UnreadableInputException;
use RoundlyConsulting\Crypto\Tests\Fixtures\FailingReadStream;

it('produces a deterministic hex digest', function (): void {
    $digest = new Digest;

    expect($digest->hex('abc'))->toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
        ->and($digest->hex('abc'))->toBe($digest->hex('abc'));
});

it('produces raw bytes of the algorithm length', function (): void {
    expect(strlen((new Digest(HashAlgorithm::Sha256))->raw('x')))->toBe(32)
        ->and(strlen((new Digest(HashAlgorithm::Sha512))->raw('x')))->toBe(64);
});

it('falls back to a plain hash only for an explicit null pepper', function (): void {
    expect((new Digest)->withPepper('data', null))->toBe((new Digest)->hex('data'));
});

it('keys an HMAC with any non-null pepper, verbatim and untrimmed', function (string $pepper): void {
    $plain = (new Digest)->hex('data');
    $peppered = (new Digest)->withPepper('data', $pepper);

    // A whitespace or empty pepper must NOT downgrade to the plain hash — it is
    // used verbatim as the HMAC key, distinct from the unkeyed digest.
    expect($peppered)->toBe(hash_hmac('sha256', 'data', $pepper))
        ->and($peppered)->not->toBe($plain);
})->with([
    'real' => ['pepper'],
    'whitespace' => ['   '],
    'leading-whitespace' => [' pepper '],
]);

it('matches a committed HMAC known-answer vector for a real pepper', function (): void {
    // RFC 4231 test case 2: key "Jefe", data "what do ya want for nothing?".
    expect((new Digest)->withPepper('what do ya want for nothing?', 'Jefe'))
        ->toBe('5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843');
});

/**
 * A temp file holding the given bytes, removed after the test.
 */
function digestTempFile(string $contents): string
{
    $path = tempnam(sys_get_temp_dir(), 'crypto-digest-');
    file_put_contents($path, $contents);
    register_shutdown_function(static fn () => @unlink($path));

    return $path;
}

/**
 * An in-memory stream holding the given bytes, rewound.
 *
 * @return resource
 */
function digestMemoryStream(string $contents)
{
    $stream = fopen('php://memory', 'r+b');
    fwrite($stream, $contents);
    rewind($stream);

    return $stream;
}

describe('file()', function (): void {
    it('matches the string digest of the same bytes for every algorithm', function (HashAlgorithm $algorithm): void {
        $contents = str_repeat("line,with,cells\n", 5000);
        $path = digestTempFile($contents);

        expect((new Digest($algorithm))->file($path))
            ->toBe((new Digest($algorithm))->hex($contents))
            ->toBe(hash_file($algorithm->value, $path));
    })->with(HashAlgorithm::cases());

    it('defaults to a lower-case sha-256 hex digest', function (): void {
        expect((new Digest)->file(digestTempFile('abc')))
            ->toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    });

    it('digests an empty file', function (): void {
        expect((new Digest)->file(digestTempFile('')))->toBe(hash('sha256', ''));
    });

    it('keys an HMAC with the pepper exactly as withPepper() does', function (?string $pepper): void {
        $contents = random_bytes(10_000);

        expect((new Digest(HashAlgorithm::Sha512))->file(digestTempFile($contents), $pepper))
            ->toBe((new Digest(HashAlgorithm::Sha512))->withPepper($contents, $pepper));
    })->with([
        'no pepper' => [null],
        'real' => ['pepper'],
        'whitespace' => ['   '],
        'empty' => [''],
    ]);

    it('never downgrades an empty pepper to the plain digest', function (): void {
        $path = digestTempFile('data');

        expect((new Digest)->file($path, ''))->toBe(hash_hmac('sha256', 'data', ''))
            ->not->toBe((new Digest)->file($path));
    });

    it('matches the RFC 4231 HMAC known-answer vector', function (): void {
        expect((new Digest)->file(digestTempFile('what do ya want for nothing?'), 'Jefe'))
            ->toBe('5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843');
    });

    it('streams a large file in flat memory', function (): void {
        $path = tempnam(sys_get_temp_dir(), 'crypto-digest-large-');
        register_shutdown_function(static fn () => @unlink($path));
        $handle = fopen($path, 'wb');
        $chunk = str_repeat('0123456789abcdef', 65_536); // 1 MiB

        for ($i = 0; $i < 16; $i++) {
            fwrite($handle, $chunk);
        }

        fclose($handle);
        unset($chunk);

        memory_reset_peak_usage();
        $before = memory_get_usage();
        $digest = (new Digest)->file($path);
        $growth = memory_get_peak_usage() - $before;

        expect($digest)->toBe(hash_file('sha256', $path))
            ->and($growth)->toBeLessThan(1024 * 1024);
    });

    it('refuses a missing file', function (): void {
        (new Digest)->file(sys_get_temp_dir().'/crypto-digest-missing-'.bin2hex(random_bytes(8)));
    })->throws(UnreadableInputException::class, 'does not exist');

    it('refuses a directory', function (): void {
        (new Digest)->file(sys_get_temp_dir());
    })->throws(UnreadableInputException::class, 'is not a file');

    it('refuses a file it cannot open', function (): void {
        $path = digestTempFile('secret');
        chmod($path, 0o000);

        try {
            (new Digest)->file($path);
        } finally {
            chmod($path, 0o600);
        }
    })->throws(UnreadableInputException::class, 'cannot be opened for reading')
        ->skip(fn (): bool => function_exists('posix_geteuid') && posix_geteuid() === 0, 'root reads any file');

    it('refuses an empty path or one with a NUL byte', function (string $path): void {
        (new Digest)->file($path);
    })->throws(UnreadableInputException::class, 'empty or contains a NUL byte')->with([
        'empty' => [''],
        'nul' => ["/tmp/a\0b"],
    ]);

    it('refuses a source that fails before its end', function (): void {
        FailingReadStream::register();

        (new Digest)->file(FailingReadStream::SCHEME.'://source');
    })->throws(UnreadableInputException::class, 'could not be read to its end');

    it('throws the package exception type', function (): void {
        expect(new ReflectionClass(UnreadableInputException::class))
            ->isSubclassOf(CryptoException::class)->toBeTrue()
            ->isFinal()->toBeTrue();
    });
});

describe('stream()', function (): void {
    it('matches the string digest of the same bytes', function (HashAlgorithm $algorithm): void {
        $contents = random_bytes(50_000);

        expect((new Digest($algorithm))->stream(digestMemoryStream($contents)))
            ->toBe((new Digest($algorithm))->hex($contents));
    })->with(HashAlgorithm::cases());

    it('hashes from the current position and leaves the pointer at the end', function (): void {
        $stream = digestMemoryStream('header,rowdata');
        fseek($stream, 7);

        expect((new Digest)->stream($stream))->toBe(hash('sha256', 'rowdata'))
            ->and(ftell($stream))->toBe(14)
            ->and(feof($stream))->toBeTrue();
    });

    it('never closes the caller\'s stream', function (): void {
        $stream = digestMemoryStream('abc');

        (new Digest)->stream($stream);
        rewind($stream);

        expect(is_resource($stream))->toBeTrue()
            ->and(stream_get_contents($stream))->toBe('abc');
    });

    it('digests a stream already at its end as empty input', function (): void {
        $stream = digestMemoryStream('abc');
        fseek($stream, 0, SEEK_END);

        expect((new Digest)->stream($stream))->toBe(hash('sha256', ''));
    });

    it('keys an HMAC with the pepper exactly as withPepper() does', function (?string $pepper): void {
        expect((new Digest)->stream(digestMemoryStream('payload'), $pepper))
            ->toBe((new Digest)->withPepper('payload', $pepper));
    })->with([
        'no pepper' => [null],
        'real' => ['pepper'],
        'empty' => [''],
    ]);

    it('refuses anything that is not an open stream', function (mixed $input, string $type): void {
        expect(fn () => (new Digest)->stream($input))
            ->toThrow(UnreadableInputException::class, "an open stream resource, [{$type}] given");
    })->with([
        'string' => ['/tmp/file.csv', 'string'],
        'null' => [null, 'null'],
        'object' => [new stdClass, 'stdClass'],
        'stream context' => [stream_context_create(), 'resource (stream-context)'],
        'closed stream' => [(static function () {
            $stream = fopen('php://memory', 'rb');
            fclose($stream);

            return $stream;
        })(), 'resource (closed)'],
    ]);

    it('refuses a write-only stream instead of digesting nothing', function (): void {
        $path = digestTempFile('abc');
        $stream = fopen($path, 'ab');

        try {
            (new Digest)->stream($stream);
        } finally {
            fclose($stream);
        }
    })->throws(UnreadableInputException::class, 'not open for reading (mode [ab])');

    it('refuses a directory handle', function (): void {
        $handle = opendir(sys_get_temp_dir());

        try {
            (new Digest)->stream($handle);
        } finally {
            closedir($handle);
        }
    })->throws(UnreadableInputException::class, 'directory handle');

    it('refuses a stream that fails before its end', function (): void {
        FailingReadStream::register();
        $stream = fopen(FailingReadStream::SCHEME.'://source', 'rb');

        (new Digest)->stream($stream);
    })->throws(UnreadableInputException::class, 'could not be read to its end');
});
