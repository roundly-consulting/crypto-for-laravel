<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Facades;

use Illuminate\Support\Facades\Facade;
use RoundlyConsulting\Crypto\CryptoManager;

/**
 * @method static \RoundlyConsulting\Crypto\Jose\Jws jws()
 * @method static \RoundlyConsulting\Crypto\Jose\Jwk jwk(\RoundlyConsulting\Crypto\Signature\Key\PublicKey $key)
 * @method static \RoundlyConsulting\Crypto\Jose\Jwk jwkFromArray(array<array-key, mixed> $members)
 * @method static \RoundlyConsulting\Crypto\Jose\Jwk jwkFromJson(string $json)
 * @method static \RoundlyConsulting\Crypto\X509\Certificate certificate(string $pem)
 * @method static \RoundlyConsulting\Crypto\X509\Chain chainFromX5c(list<string> $x5c)
 * @method static \RoundlyConsulting\Crypto\X509\Chain chainFromPemBundle(string $bundle)
 * @method static \RoundlyConsulting\Crypto\Hash\Hmac hmac(\RoundlyConsulting\Crypto\Hash\HashAlgorithm $algorithm = \RoundlyConsulting\Crypto\Hash\HashAlgorithm::Sha256)
 * @method static \RoundlyConsulting\Crypto\Hash\Digest digest(\RoundlyConsulting\Crypto\Hash\HashAlgorithm $algorithm = \RoundlyConsulting\Crypto\Hash\HashAlgorithm::Sha256)
 * @method static bool constantTimeEquals(string $known, string $user)
 * @method static \RoundlyConsulting\Crypto\Signature\Hs hs(\RoundlyConsulting\Crypto\Signature\Key\HmacSecret $key, \RoundlyConsulting\Crypto\Signature\Algorithm $algorithm = \RoundlyConsulting\Crypto\Signature\Algorithm::HS256)
 * @method static \RoundlyConsulting\Crypto\Signature\Rs rs(\RoundlyConsulting\Crypto\Signature\Key\RsaKey $key, \RoundlyConsulting\Crypto\Signature\Algorithm $algorithm = \RoundlyConsulting\Crypto\Signature\Algorithm::RS256)
 * @method static \RoundlyConsulting\Crypto\Signature\Es es(\RoundlyConsulting\Crypto\Signature\Key\EcKey $key)
 * @method static \RoundlyConsulting\Crypto\Signature\EdDSA eddsa(\RoundlyConsulting\Crypto\Signature\Key\OkpKey $key)
 * @method static \RoundlyConsulting\Crypto\Signature\KeyVerifier verifier()
 * @method static \RoundlyConsulting\Crypto\Signature\Key\HmacSecret generateHmacSecret(int $bytes = 32)
 * @method static \RoundlyConsulting\Crypto\Cose\CborDecoder cbor()
 * @method static \RoundlyConsulting\Crypto\Signature\Key\PublicKey coseKey(array<int|string, mixed> $cose)
 * @method static \RoundlyConsulting\Crypto\Cose\AuthenticatorData authenticatorData(string $bytes)
 * @method static \RoundlyConsulting\Crypto\Otp\Totp totp(\RoundlyConsulting\Crypto\Otp\OtpAlgorithm $algorithm = \RoundlyConsulting\Crypto\Otp\OtpAlgorithm::Sha1, int $digits = 6, int $period = 30)
 * @method static \RoundlyConsulting\Crypto\Otp\Hotp hotp(\RoundlyConsulting\Crypto\Otp\OtpAlgorithm $algorithm = \RoundlyConsulting\Crypto\Otp\OtpAlgorithm::Sha1, int $digits = 6)
 * @method static string provisioningUri(string $secret, string $label, string $issuer, \RoundlyConsulting\Crypto\Otp\OtpAlgorithm $algorithm = \RoundlyConsulting\Crypto\Otp\OtpAlgorithm::Sha1, int $digits = 6, int $period = 30)
 * @method static string randomBytes(int $length)
 * @method static string randomToken(int $length = 40)
 * @method static string randomSecret(int $chars = 32)
 * @method static string base64UrlEncode(string $bytes)
 * @method static string base64UrlDecode(string $text)
 * @method static string base64Encode(string $bytes)
 * @method static string base64Decode(string $text)
 * @method static string base32Encode(string $bytes)
 * @method static string base32Decode(string $base32)
 * @method static string hexEncode(string $bytes)
 * @method static string hexDecode(string $hex)
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
