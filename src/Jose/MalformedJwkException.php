<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Jose;

use RoundlyConsulting\Crypto\Exceptions\CryptoException;

/**
 * Thrown when a JWK document cannot be described, or cannot be trusted to mean
 * what it says: an unsupported key type or curve, a missing or malformed member,
 * an unknown member, private key material, or an oversized document.
 *
 * Every message names the offending member and why it was refused — a JWK is
 * attacker-facing input, and "invalid JWK" tells the developer nothing.
 */
final class MalformedJwkException extends CryptoException
{
    public static function unsupportedKeyType(string $kty): self
    {
        return new self("The JWK key type [{$kty}] is not supported; expected one of RSA, EC, OKP.");
    }

    public static function missingMember(string $member): self
    {
        return new self("The JWK is missing the required member \"{$member}\".");
    }

    public static function invalidMember(string $member, string $reason): self
    {
        return new self("The JWK member \"{$member}\" {$reason}.");
    }

    /**
     * @param  list<string>  $found
     */
    public static function privateMembersRejected(array $found): self
    {
        $names = implode('", "', $found);

        return new self("The JWK carries private member(s) \"{$names}\" — only public JWKs are accepted.");
    }

    public static function unknownMember(string $member): self
    {
        return new self("The JWK member \"{$member}\" is not recognised for this key type and is rejected.");
    }

    public static function unsupportedCurve(string $crv): self
    {
        return new self("The JWK curve [{$crv}] is not supported; expected one of P-256, P-384, P-521 (EC) or Ed25519 (OKP).");
    }

    public static function tooLarge(int $bytes, int $max): self
    {
        return new self("The JWK input is {$bytes} bytes, over the {$max}-byte cap.");
    }

    public static function malformedJson(string $reason): self
    {
        return new self("The JWK document is not valid JSON: {$reason}.");
    }
}
