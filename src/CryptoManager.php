<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto;

use RoundlyConsulting\Crypto\Asn1\DerDecoder;
use RoundlyConsulting\Crypto\Codec\Base32;
use RoundlyConsulting\Crypto\Codec\Base64;
use RoundlyConsulting\Crypto\Codec\Base64Url;
use RoundlyConsulting\Crypto\Codec\Hex;
use RoundlyConsulting\Crypto\Cose\AuthenticatorData;
use RoundlyConsulting\Crypto\Cose\CborDecoder;
use RoundlyConsulting\Crypto\Cose\CoseKey;
use RoundlyConsulting\Crypto\Hash\ConstantTime;
use RoundlyConsulting\Crypto\Hash\Digest;
use RoundlyConsulting\Crypto\Hash\HashAlgorithm;
use RoundlyConsulting\Crypto\Hash\Hmac;
use RoundlyConsulting\Crypto\Jose\Jwk;
use RoundlyConsulting\Crypto\Jose\Jws;
use RoundlyConsulting\Crypto\Jose\MalformedJwkException;
use RoundlyConsulting\Crypto\Otp\Hotp;
use RoundlyConsulting\Crypto\Otp\OtpAlgorithm;
use RoundlyConsulting\Crypto\Otp\ProvisioningUri;
use RoundlyConsulting\Crypto\Otp\Totp;
use RoundlyConsulting\Crypto\Random\Bytes;
use RoundlyConsulting\Crypto\Random\Secret;
use RoundlyConsulting\Crypto\Random\Token;
use RoundlyConsulting\Crypto\Signature\Algorithm;
use RoundlyConsulting\Crypto\Signature\EdDSA;
use RoundlyConsulting\Crypto\Signature\Es;
use RoundlyConsulting\Crypto\Signature\Hs;
use RoundlyConsulting\Crypto\Signature\Key\EcKey;
use RoundlyConsulting\Crypto\Signature\Key\HmacSecret;
use RoundlyConsulting\Crypto\Signature\Key\OkpKey;
use RoundlyConsulting\Crypto\Signature\Key\PublicKey;
use RoundlyConsulting\Crypto\Signature\Key\RsaKey;
use RoundlyConsulting\Crypto\Signature\KeyLoadException;
use RoundlyConsulting\Crypto\Signature\KeyVerifier;
use RoundlyConsulting\Crypto\Signature\Rs;
use RoundlyConsulting\Crypto\X509\Certificate;
use RoundlyConsulting\Crypto\X509\Chain;
use RoundlyConsulting\Crypto\X509\InvalidChainException;
use RoundlyConsulting\Crypto\X509\MalformedCertificateException;
use SensitiveParameter;

/**
 * A discoverability front for the package's whole toolbox.
 *
 * Fronted by the {@see Facades\Crypto} facade so that typing `Crypto::` reveals
 * every entry point — codecs, CSPRNG, hashing, signers, JOSE, COSE, and OTP.
 * Every helper takes key material and knobs as explicit arguments; this manager
 * reads no config and holds no secret. The purely-static codecs and CSPRNG are
 * surfaced as passthroughs returning the computed value; stateful entry points
 * and keyed signers are returned as short-lived instances.
 */
final class CryptoManager
{
    // ── JOSE / JWS ──────────────────────────────────────────────────────────

    public function jws(): Jws
    {
        return new Jws;
    }

    // ── JWK (RFC 7517 / RFC 7638) ───────────────────────────────────────────

    /**
     * Serialize a public key as a JWK — the curve and coordinate padding come
     * from the key itself.
     *
     * @throws MalformedJwkException|KeyLoadException
     */
    public function jwk(PublicKey $key): Jwk
    {
        return Jwk::fromPublicKey($key);
    }

    /**
     * @param  array<array-key, mixed>  $members
     *
     * @throws MalformedJwkException
     */
    public function jwkFromArray(array $members): Jwk
    {
        return Jwk::fromArray($members);
    }

    /**
     * @throws MalformedJwkException
     */
    public function jwkFromJson(string $json): Jwk
    {
        return Jwk::fromJson($json);
    }

    // ── X.509 (RFC 5280) ────────────────────────────────────────────────────

    /**
     * Parse a PEM certificate. Every accessor on the result is a FACT — crypto
     * reports what a certificate says, it never rules on whether to trust it.
     *
     * @throws MalformedCertificateException
     */
    public function certificate(string $pem): Certificate
    {
        return Certificate::fromPem($pem);
    }

    /**
     * A chain from a JOSE `x5c` header: standard base64 DER, leaf first.
     *
     * @param  list<string>  $x5c
     *
     * @throws MalformedCertificateException|InvalidChainException
     */
    public function chainFromX5c(array $x5c): Chain
    {
        return Chain::fromX5c($x5c);
    }

    /**
     * A chain from a concatenated PEM bundle (leaf + chain).
     *
     * @throws MalformedCertificateException|InvalidChainException
     */
    public function chainFromPemBundle(string $bundle): Chain
    {
        return Chain::fromPemBundle($bundle);
    }

    // ── ASN.1 / DER (X.690) ─────────────────────────────────────────────────

    /**
     * A strict DER reader — the CBOR decoder's counterpart for the other encoding
     * certificates arrive in. A parser, never a trust store.
     */
    public function derDecoder(): DerDecoder
    {
        return new DerDecoder;
    }

    // ── Hashing ─────────────────────────────────────────────────────────────

    public function hmac(HashAlgorithm $algorithm = HashAlgorithm::Sha256): Hmac
    {
        return new Hmac($algorithm);
    }

    public function digest(HashAlgorithm $algorithm = HashAlgorithm::Sha256): Digest
    {
        return new Digest($algorithm);
    }

    public function constantTimeEquals(string $known, #[SensitiveParameter] string $user): bool
    {
        return ConstantTime::equals($known, $user);
    }

    // ── Keyed signers (explicit key material, zero-config) ──────────────────

    public function hs(HmacSecret $key, Algorithm $algorithm = Algorithm::HS256): Hs
    {
        return new Hs($key, $algorithm);
    }

    public function rs(RsaKey $key, Algorithm $algorithm = Algorithm::RS256): Rs
    {
        return new Rs($key, $algorithm);
    }

    public function es(EcKey $key): Es
    {
        return new Es($key);
    }

    public function eddsa(OkpKey $key): EdDSA
    {
        return new EdDSA($key);
    }

    public function verifier(): KeyVerifier
    {
        return new KeyVerifier;
    }

    /**
     * Generate a fresh HMAC secret (≥256 bits of CSPRNG). Returned, never held —
     * the manager caches no key material.
     */
    public function generateHmacSecret(int $bytes = 32): HmacSecret
    {
        return HmacSecret::generate($bytes);
    }

    // ── COSE / WebAuthn ─────────────────────────────────────────────────────

    public function cbor(): CborDecoder
    {
        return new CborDecoder;
    }

    /**
     * @param  array<int|string, mixed>  $cose
     */
    public function coseKey(array $cose): PublicKey
    {
        return CoseKey::fromDecoded($cose);
    }

    public function authenticatorData(string $bytes): AuthenticatorData
    {
        return AuthenticatorData::parse($bytes);
    }

    // ── OTP ─────────────────────────────────────────────────────────────────

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

    public function provisioningUri(
        #[SensitiveParameter] string $secret,
        string $label,
        string $issuer,
        OtpAlgorithm $algorithm = OtpAlgorithm::Sha1,
        int $digits = 6,
        int $period = 30,
    ): string {
        return ProvisioningUri::totp($secret, $label, $issuer, $algorithm, $digits, $period);
    }

    // ── CSPRNG ──────────────────────────────────────────────────────────────

    public function randomBytes(int $length): string
    {
        return Bytes::generate($length);
    }

    public function randomToken(int $length = 40): string
    {
        return Token::urlSafe($length);
    }

    public function randomSecret(int $chars = 32): string
    {
        return Secret::base32($chars);
    }

    // ── Codecs ──────────────────────────────────────────────────────────────

    public function base64UrlEncode(string $bytes): string
    {
        return Base64Url::encode($bytes);
    }

    public function base64UrlDecode(string $text): string
    {
        return Base64Url::decode($text);
    }

    public function base64Encode(string $bytes): string
    {
        return Base64::encode($bytes);
    }

    public function base64Decode(string $text): string
    {
        return Base64::decode($text);
    }

    public function base32Encode(string $bytes): string
    {
        return Base32::encode($bytes);
    }

    public function base32Decode(string $base32): string
    {
        return Base32::decode($base32);
    }

    public function hexEncode(string $bytes): string
    {
        return Hex::encode($bytes);
    }

    public function hexDecode(string $hex): string
    {
        return Hex::decode($hex);
    }
}
