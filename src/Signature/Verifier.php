<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Signature;

use SensitiveParameter;

/**
 * Verifies a detached signature over a message for exactly one algorithm.
 *
 * A verifier is bound to a single algorithm at construction; it never inspects
 * a token header to choose one, so an `alg` downgrade cannot influence it.
 */
interface Verifier
{
    public function algorithm(): Algorithm;

    /**
     * Whether the signature is valid for the message under this verifier's key.
     *
     * The signature is `#[SensitiveParameter]`, and an implementation marks it too: beside
     * the signing input it rebuilds a JWS bearer token, so it never belongs in a stack trace.
     */
    public function verify(string $message, #[SensitiveParameter] string $signature): bool;
}
