<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Facades;

use Illuminate\Support\Facades\Facade;
use RoundlyConsulting\Crypto\CryptoManager;

/**
 * @method static \RoundlyConsulting\Crypto\Jose\Jws jws()
 * @method static \RoundlyConsulting\Crypto\Hash\Hmac hmac(\RoundlyConsulting\Crypto\Hash\HashAlgorithm $algorithm = \RoundlyConsulting\Crypto\Hash\HashAlgorithm::Sha256)
 * @method static \RoundlyConsulting\Crypto\Hash\Digest digest(\RoundlyConsulting\Crypto\Hash\HashAlgorithm $algorithm = \RoundlyConsulting\Crypto\Hash\HashAlgorithm::Sha256)
 * @method static \RoundlyConsulting\Crypto\Signature\KeyVerifier verifier()
 * @method static \RoundlyConsulting\Crypto\Cose\CborDecoder cbor()
 * @method static \RoundlyConsulting\Crypto\Otp\Totp totp(\RoundlyConsulting\Crypto\Otp\OtpAlgorithm $algorithm = \RoundlyConsulting\Crypto\Otp\OtpAlgorithm::Sha1, int $digits = 6, int $period = 30)
 * @method static \RoundlyConsulting\Crypto\Otp\Hotp hotp(\RoundlyConsulting\Crypto\Otp\OtpAlgorithm $algorithm = \RoundlyConsulting\Crypto\Otp\OtpAlgorithm::Sha1, int $digits = 6)
 *
 * @see CryptoManager
 */
final class Crypto extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return CryptoManager::class;
    }
}
