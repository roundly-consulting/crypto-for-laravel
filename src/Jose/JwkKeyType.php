<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Jose;

/**
 * The JWK key types this package can describe — RFC 7518 §6.1 (`RSA`, `EC`) and
 * RFC 8037 §2 (`OKP`).
 *
 * The backing value is the `kty` member verbatim, and it is matched
 * case-sensitively: `ec` is not `EC`.
 */
enum JwkKeyType: string
{
    case Rsa = 'RSA';
    case Ec = 'EC';
    case Okp = 'OKP';
}
