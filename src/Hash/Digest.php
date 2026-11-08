<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Hash;

use HashContext;
use SensitiveParameter;

/**
 * Deterministic one-way digests for at-rest lookups, cache keys and file checksums.
 *
 * Deterministic by design: the same input always yields the same digest, which
 * is what makes a unique-index equality lookup possible. An optional pepper
 * switches the plain hash to an HMAC for defence-in-depth.
 *
 * The data is `#[SensitiveParameter]`: what gets digested for an at-rest lookup
 * is a token, a password or personal data, never something a stack trace needs.
 * A path or a stream is not: neither carries the bytes into a trace.
 *
 * {@see file()} and {@see stream()} digest in fixed-size chunks, so memory stays
 * flat however large the input. They return lower-case hex only, the form a
 * checksum column, an ETag or a dedupe key stores; for raw bytes, hex-decode the
 * result. Each takes the same optional pepper as {@see withPepper()} and gives
 * the same value for the same bytes.
 */
final readonly class Digest
{
    public function __construct(private HashAlgorithm $algorithm = HashAlgorithm::Sha256) {}

    /**
     * The raw-bytes digest of the data.
     */
    public function raw(#[SensitiveParameter] string $data): string
    {
        return hash($this->algorithm->value, $data, true);
    }

    /**
     * The lower-case hexadecimal digest of the data.
     */
    public function hex(#[SensitiveParameter] string $data): string
    {
        return hash($this->algorithm->value, $data, false);
    }

    /**
     * A hexadecimal digest, HMAC'd with the pepper when one is supplied.
     *
     * The plain-vs-keyed choice is explicit, never inferred from the pepper's
     * content: only `null` selects the plain digest. Any non-null pepper — even
     * whitespace or an empty string — is used verbatim as the HMAC key (never
     * trimmed), so a caller can never silently downgrade a keyed digest to an
     * unkeyed one by passing a blank string.
     */
    public function withPepper(#[SensitiveParameter] string $data, #[SensitiveParameter] ?string $pepper): string
    {
        return $pepper === null
            ? hash($this->algorithm->value, $data, false)
            : hash_hmac($this->algorithm->value, $data, $pepper, false);
    }

    /**
     * The lower-case hexadecimal digest of a file, read in chunks so memory stays flat.
     *
     * The path is anything `fopen()` opens for reading: a local path or a stream-wrapper
     * URL. For a Laravel disk, pass `Storage::disk($disk)->readStream($path)` to
     * {@see stream()} instead. The pepper works as in {@see withPepper()}: `null` gives the
     * plain digest, any other string (even an empty one) keys an HMAC.
     *
     * @throws UnreadableInputException when the path is empty, missing, a directory, cannot
     *                                  be opened, or cannot be read to its end
     */
    public function file(string $path, #[SensitiveParameter] ?string $pepper = null): string
    {
        if ($path === '' || str_contains($path, "\0")) {
            throw UnreadableInputException::invalidPath();
        }

        // Silenced: a stream wrapper without `url_stat` warns here, and the open below
        // reports the real failure.
        if (@is_dir($path)) {
            throw UnreadableInputException::notAFile($path);
        }

        $handle = @fopen($path, 'rb');

        if ($handle === false) {
            throw @file_exists($path)
                ? UnreadableInputException::unreadableFile($path)
                : UnreadableInputException::missingFile($path);
        }

        try {
            return $this->stream($handle, $pepper);
        } finally {
            fclose($handle);
        }
    }

    /**
     * The lower-case hexadecimal digest of a stream, read in chunks so memory stays flat.
     *
     * Reads from the stream's CURRENT position to its end, so a caller that already
     * consumed a header gets the digest of the rest; rewind first to digest it all. The
     * stream is left open, positioned at its end; closing it stays the caller's job. The
     * pepper works as in {@see withPepper()}.
     *
     * @param  mixed  $stream  an open stream resource, opened for reading
     *
     * @throws UnreadableInputException when the value is not an open, readable stream, or
     *                                  the read stops before the end
     */
    public function stream(mixed $stream, #[SensitiveParameter] ?string $pepper = null): string
    {
        if (! is_resource($stream) || get_resource_type($stream) !== 'stream') {
            throw UnreadableInputException::notAStream(get_debug_type($stream));
        }

        $meta = stream_get_meta_data($stream);

        if ($meta['stream_type'] === 'dir') {
            throw UnreadableInputException::directoryHandle();
        }

        // A write-only stream reads as empty, which would digest to the hash of nothing.
        if (! str_contains($meta['mode'], 'r') && ! str_contains($meta['mode'], '+')) {
            throw UnreadableInputException::notReadable($meta['mode']);
        }

        $context = $this->context($pepper);

        // Silenced: a failing read only raises a notice; the end-of-stream check below
        // turns any early stop into an exception.
        @hash_update_stream($context, $stream);

        if (! feof($stream)) {
            throw UnreadableInputException::readFailed();
        }

        return hash_final($context, false);
    }

    /**
     * A plain or HMAC hashing context.
     *
     * `hash_init()` refuses an empty HMAC key, where `hash_hmac()` accepts it. HMAC pads
     * every key shorter than the block size with zero bytes (RFC 2104), so the empty key
     * and a single zero byte are the same key; the substitution gives exactly the value
     * {@see withPepper()} gives for an empty pepper.
     */
    private function context(#[SensitiveParameter] ?string $pepper): HashContext
    {
        if ($pepper === null) {
            return hash_init($this->algorithm->value);
        }

        return hash_init($this->algorithm->value, HASH_HMAC, $pepper === '' ? "\0" : $pepper);
    }
}
