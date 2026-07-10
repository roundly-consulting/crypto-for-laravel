<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto;

use RoundlyConsulting\Crypto\Cose\CborDecoder;
use RoundlyConsulting\Crypto\Hash\Digest;
use RoundlyConsulting\Crypto\Hash\HashAlgorithm;
use RoundlyConsulting\Crypto\Hash\Hmac;
use RoundlyConsulting\Crypto\Jose\Jws;
use RoundlyConsulting\Crypto\Otp\Hotp;
use RoundlyConsulting\Crypto\Otp\OtpAlgorithm;
use RoundlyConsulting\Crypto\Otp\Totp;
use RoundlyConsulting\Crypto\Signature\KeyVerifier;

/**
 * A discoverability front for the package's key-less, stateless entry points.
 *
 * Fronted by the {@see Facades\Crypto} facade. Every factory helper takes key
 * material and knobs as explicit arguments — this manager reads no config and
 * holds no secret.
 */
final class CryptoManager
{
    public function jws(): Jws
    {
        return new Jws;
    }

    public function hmac(HashAlgorithm $algorithm = HashAlgorithm::Sha256): Hmac
    {
        return new Hmac($algorithm);
    }

    public function digest(HashAlgorithm $algorithm = HashAlgorithm::Sha256): Digest
    {
        return new Digest($algorithm);
    }

    public function verifier(): KeyVerifier
    {
        return new KeyVerifier;
    }

    public function cbor(): CborDecoder
    {
        return new CborDecoder;
    }

    public function totp(
        OtpAlgorithm $algorithm = OtpAlgorithm::Sha1,
        int $digits = 6,
        int $period = 30,
    ): Totp {
        return new Totp($algorithm, $digits, $period);
    }

    public function hotp(OtpAlgorithm $algorithm = OtpAlgorithm::Sha1, int $digits = 6): Hotp
    {
        return new Hotp($algorithm, $digits);
    }
}
