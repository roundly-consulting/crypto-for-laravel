<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Jose;

use Carbon\CarbonImmutable;

/**
 * An immutable bag of decoded JWS payload claims with typed, validating
 * accessors.
 *
 * {@see Jws::verify()} returns a `Claims` only after the signature check passes.
 * Temporal validation (`exp`/`nbf`/`iat`) is deliberately NOT applied during
 * verification — it is opt-in via {@see self::assertTemporal()} — so JOSE-only
 * consumers that sign rather than validate JWT lifetimes are not forced through
 * JWT semantics. Claim policy (issuer/audience/scope) stays with the caller.
 */
final readonly class Claims
{
    /**
     * @param  array<string, mixed>  $claims
     */
    public function __construct(private array $claims) {}

    public function has(string $name): bool
    {
        return array_key_exists($name, $this->claims);
    }

    public function get(string $name): mixed
    {
        return $this->claims[$name] ?? null;
    }

    /**
     * @throws ClaimMismatchException when the claim is absent
     */
    public function require(string $name): mixed
    {
        if (! $this->has($name)) {
            throw ClaimMismatchException::missing($name);
        }

        return $this->claims[$name];
    }

    /**
     * @throws ClaimMismatchException when absent or not a string
     */
    public function string(string $name): string
    {
        $value = $this->require($name);

        if (! is_string($value)) {
            throw ClaimMismatchException::notA($name, 'a string');
        }

        return $value;
    }

    /**
     * @throws ClaimMismatchException when absent or not an integer
     */
    public function int(string $name): int
    {
        $value = $this->require($name);

        // JSON numbers decode to int|float; a whole float (e.g. 1.0) is fine, a
        // fractional timestamp is not.
        if (is_int($value)) {
            return $value;
        }

        if (is_float($value) && floor($value) === $value) {
            return (int) $value;
        }

        throw ClaimMismatchException::notA($name, 'an integer');
    }

    /**
     * @return list<string>
     *
     * @throws ClaimMismatchException when absent or not a list of strings
     */
    public function list(string $name): array
    {
        $value = $this->require($name);

        if (! is_array($value) || ! array_is_list($value)) {
            throw ClaimMismatchException::notA($name, 'a list');
        }

        foreach ($value as $item) {
            if (! is_string($item)) {
                throw ClaimMismatchException::notA($name, 'a list of strings');
            }
        }

        /** @var list<string> $value */
        return $value;
    }

    /**
     * @return array<string, mixed>
     */
    public function all(): array
    {
        return $this->claims;
    }

    /**
     * Opt-in temporal validation (RFC 7519): `exp` is required and must be in
     * the future; `nbf`/`iat`, when present, must not be in the future. The
     * leeway (seconds) absorbs small clock skew between issuer and verifier.
     *
     * @throws ClaimMismatchException|TokenExpiredException|TokenNotYetValidException
     */
    public function assertTemporal(int $leeway = 0): void
    {
        $now = CarbonImmutable::now()->getTimestamp();

        if ($now - $leeway >= $this->int('exp')) {
            throw TokenExpiredException::expired();
        }

        if ($this->has('nbf') && $this->int('nbf') > $now + $leeway) {
            throw TokenNotYetValidException::notYetValid();
        }

        if ($this->has('iat') && $this->int('iat') > $now + $leeway) {
            throw TokenNotYetValidException::issuedInFuture();
        }
    }
}
