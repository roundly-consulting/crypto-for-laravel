<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Hash;

/**
 * The digest algorithms supported for HMAC and plain hashing.
 *
 * The backing value is the exact name understood by PHP's hash() / hash_hmac().
 */
enum HashAlgorithm: string
{
    case Sha1 = 'sha1';
    case Sha256 = 'sha256';
    case Sha384 = 'sha384';
    case Sha512 = 'sha512';
}
