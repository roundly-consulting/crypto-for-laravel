<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Otp;

use Carbon\CarbonImmutable;
use RoundlyConsulting\Crypto\Hash\ConstantTime;
use SensitiveParameter;

/**
 * RFC 6238 time-based one-time passwords (TOTP).
 *
 * Verification checks every step in the drift window without an early return, so
 * a match late in the window costs the same as one early — the loop leaks no
 * timing — and every code comparison runs through {@see ConstantTime}.
 */
final readonly class Totp
{
    private Hotp $hotp;

    public function __construct(
        private OtpAlgorithm $algorithm = OtpAlgorithm::Sha1,
        private int $digits = 6,
        private int $period = 30,
    ) {
        if ($period < 1) {
            throw InvalidOtpParameterException::period($period);
        }

        // Hotp validates the digit range.
        $this->hotp = new Hotp($algorithm, $digits);
    }

    /**
     * The TOTP value for a base32 secret at an explicit timestep index.
     */
    public function at(#[SensitiveParameter] string $secret, int $timestep): string
    {
        return $this->hotp->at($secret, $timestep);
    }

    /**
     * The TOTP value at a unix timestamp (defaults to now).
     */
    public function codeAt(#[SensitiveParameter] string $secret, ?int $timestamp = null): string
    {
        return $this->at($secret, $this->timestepAt($timestamp ?? $this->now()));
    }

    /**
     * The timestep index (counter) for a unix timestamp.
     */
    public function timestepAt(int $timestamp): int
    {
        return intdiv($timestamp, $this->period);
    }

    /**
     * Verify a code against the drift window, returning the matched timestep or
     * false. Malformed codes are rejected before any HMAC work is done.
     *
     * @return int|false the matched timestep index
     */
    public function verify(
        #[SensitiveParameter] string $secret,
        #[SensitiveParameter] string $code,
        int $window = 1,
        ?int $timestamp = null,
    ): int|false {
        if ($window < 0) {
            throw InvalidOtpParameterException::window($window);
        }

        if (! $this->isWellFormed($code)) {
            return false;
        }

        $current = $this->timestepAt($timestamp ?? $this->now());
        $matched = false;

        for ($step = $current - $window; $step <= $current + $window; $step++) {
            if (ConstantTime::equals($this->at($secret, $step), $code)) {
                $matched = $step;
            }
        }

        return $matched;
    }

    private function isWellFormed(string $code): bool
    {
        return strlen($code) === $this->digits && ctype_digit($code);
    }

    private function now(): int
    {
        // CarbonImmutable so tests can pin the clock with setTestNow().
        return CarbonImmutable::now()->getTimestamp();
    }
}
