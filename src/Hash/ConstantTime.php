<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Hash;

use SensitiveParameter;

/**
 * A discoverable wrapper around hash_equals for constant-time comparisons.
 *
 * Every secret / tag / MAC comparison in the package routes through here so a
 * verification never leaks, through timing, how much of a value matched.
 */
final class ConstantTime
{
    /**
     * Compare two strings in length-independent constant time.
     *
     * @param  string  $known  the trusted/expected value
     * @param  string  $user  the attacker-influenced value
     */
    public static function equals(string $known, #[SensitiveParameter] string $user): bool
    {
        return hash_equals($known, $user);
    }
}
