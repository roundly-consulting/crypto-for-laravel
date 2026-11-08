<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Hash;

use RoundlyConsulting\Crypto\Exceptions\CryptoException;

/**
 * A file or stream {@see Digest} cannot read to its end. A digest of half the bytes would
 * pass for the digest of the whole input, so every way the read can come up short throws
 * instead of returning a value.
 */
final class UnreadableInputException extends CryptoException
{
    public static function invalidPath(): self
    {
        return new self('The path to digest is empty or contains a NUL byte.');
    }

    public static function missingFile(string $path): self
    {
        return new self("The file [{$path}] does not exist.");
    }

    public static function notAFile(string $path): self
    {
        return new self("The path [{$path}] is not a file.");
    }

    public static function unreadableFile(string $path): self
    {
        return new self("The file [{$path}] cannot be opened for reading.");
    }

    public static function notAStream(string $type): self
    {
        return new self("Expected an open stream resource, [{$type}] given.");
    }

    public static function directoryHandle(): self
    {
        return new self('A directory handle cannot be digested; pass a file stream.');
    }

    public static function notReadable(string $mode): self
    {
        return new self("The stream is not open for reading (mode [{$mode}]).");
    }

    public static function readFailed(): self
    {
        return new self('The stream could not be read to its end.');
    }
}
