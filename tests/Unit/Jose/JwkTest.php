<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Codec\Base64Url;
use RoundlyConsulting\Crypto\Jose\Jwk;
use RoundlyConsulting\Crypto\Jose\JwkKeyType;
use RoundlyConsulting\Crypto\Jose\MalformedJwkException;
use RoundlyConsulting\Crypto\Signature\Algorithm;
use RoundlyConsulting\Crypto\Signature\Key\EcKey;
use RoundlyConsulting\Crypto\Signature\Key\OkpKey;
use RoundlyConsulting\Crypto\Signature\Key\PublicKey;
use RoundlyConsulting\Crypto\Signature\Key\RsaKey;
use RoundlyConsulting\Crypto\Signature\KeyLoadException;
use RoundlyConsulting\Crypto\Signature\Rs;
use RoundlyConsulting\Crypto\Signature\WeakKeyException;
use RoundlyConsulting\Crypto\Testing\TestKeys;

/**
 * A valid EC JWK's members, for mutating in the negative matrix.
 *
 * @return array<string, string>
 */
function ecJwkMembers(string $curve = 'P-256'): array
{
    return Jwk::fromPublicKey(EcKey::generate($curve))->toArray();
}

/**
 * @return array<string, string>
 */
function rsaJwkMembers(): array
{
    return Jwk::fromPublicKey(RsaKey::public(keyPem('rsa-public')))->toArray();
}

// ── key → JWK ───────────────────────────────────────────────────────────────

it('describes an EC key with its own curve and coordinate length', function (string $curve, string $alg, int $bytes): void {
    $jwk = Jwk::fromPublicKey(EcKey::generate($curve));

    expect($jwk->keyType())->toBe(JwkKeyType::Ec)
        ->and($jwk->algorithm()->value)->toBe($alg)
        ->and(array_keys($jwk->toArray()))->toBe(['crv', 'kty', 'x', 'y'])
        ->and($jwk->toArray()['crv'])->toBe($curve)
        ->and(strlen(Base64Url::decode($jwk->toArray()['x'])))->toBe($bytes)
        ->and(strlen(Base64Url::decode($jwk->toArray()['y'])))->toBe($bytes);
})->with([
    ['P-256', 'ES256', 32],
    ['P-384', 'ES384', 48],
    ['P-521', 'ES512', 66],
]);

it('never labels a larger curve as P-256', function (): void {
    $jwk = Jwk::fromPublicKey(EcKey::generate('P-384'));

    expect($jwk->toArray()['crv'])->not->toBe('P-256')
        ->and($jwk->toArray()['crv'])->toBe('P-384');
});

it('describes an RSA key', function (): void {
    $jwk = Jwk::fromPublicKey(RsaKey::public(keyPem('rsa-public')));

    expect($jwk->keyType())->toBe(JwkKeyType::Rsa)
        ->and($jwk->algorithm())->toBe(Algorithm::RS256)
        ->and(array_keys($jwk->toArray()))->toBe(['e', 'kty', 'n'])
        ->and($jwk->toArray()['e'])->toBe('AQAB');
});

it('describes an Ed25519 key', function (): void {
    $jwk = Jwk::fromPublicKey(TestKeys::ed25519());

    expect($jwk->keyType())->toBe(JwkKeyType::Okp)
        ->and($jwk->algorithm())->toBe(Algorithm::EdDSA)
        ->and(array_keys($jwk->toArray()))->toBe(['crv', 'kty', 'x'])
        ->and($jwk->toArray()['crv'])->toBe('Ed25519')
        ->and(strlen(Base64Url::decode($jwk->toArray()['x'])))->toBe(32)
        ->and($jwk->toArray())->not->toHaveKey('y');
})->skip(fn (): bool => ! TestKeys::supportsEd25519(), 'ext-sodium is not loaded');

it('rejects a public key type it cannot describe', function (): void {
    $key = new class implements PublicKey
    {
        public function algorithm(): Algorithm
        {
            return Algorithm::HS256;
        }

        public function verifier(): RoundlyConsulting\Crypto\Signature\Verifier
        {
            throw new RuntimeException('never called');
        }
    };

    expect(fn (): Jwk => Jwk::fromPublicKey($key))->toThrow(MalformedJwkException::class);
});

it('serializes straight into a JOSE header', function (): void {
    $jwk = Jwk::fromPublicKey(EcKey::generate());

    $header = json_encode(['alg' => 'ES256', 'jwk' => $jwk], JSON_THROW_ON_ERROR);

    expect($header)->toContain('"kty":"EC"')
        ->and(json_decode($header, true, 512, JSON_THROW_ON_ERROR)['jwk'])->toBe($jwk->toArray());
});

// ── JWK → key ───────────────────────────────────────────────────────────────

it('round-trips an EC key through its JWK', function (string $curve): void {
    $key = EcKey::generate($curve);
    $jwk = Jwk::fromPublicKey($key);

    $parsed = Jwk::fromArray($jwk->toArray())->publicKey();

    expect($parsed)->toBeInstanceOf(EcKey::class)
        ->and($parsed->algorithm())->toBe($key->algorithm());

    $message = 'the round-trip must produce a key that verifies real signatures';
    $signature = $key->verifier()->sign($message);

    expect($parsed->verifier()->verify($message, $signature))->toBeTrue();
})->with(['P-256', 'P-384', 'P-521']);

it('round-trips an RSA key through its JWK', function (): void {
    $key = RsaKey::private(keyPem('rsa-private'));
    $parsed = Jwk::fromArray(Jwk::fromPublicKey($key)->toArray())->publicKey();

    $signature = $key->verifier()->sign('payload');

    expect($parsed)->toBeInstanceOf(RsaKey::class)
        ->and($parsed->verifier()->verify('payload', $signature))->toBeTrue();
});

it('round-trips an Ed25519 key through its JWK', function (): void {
    $key = TestKeys::ed25519();
    $parsed = Jwk::fromArray(Jwk::fromPublicKey($key)->toArray())->publicKey();

    $signature = $key->verifier()->sign('payload');

    expect($parsed)->toBeInstanceOf(OkpKey::class)
        ->and($parsed->verifier()->verify('payload', $signature))->toBeTrue();
})->skip(fn (): bool => ! TestKeys::supportsEd25519(), 'ext-sodium is not loaded');

it('parses the RFC 7638 document into a usable RSA key', function (): void {
    $jwk = Jwk::fromJson(readFixture('rfc7638-a1.json'));

    expect($jwk->publicKey())->toBeInstanceOf(RsaKey::class)
        ->and($jwk->kid())->toBe('2011-04-29')
        ->and($jwk->alg())->toBe('RS256')
        ->and($jwk->use())->toBeNull()
        ->and($jwk->toArray())->toBe([
            'alg' => 'RS256',
            'e' => 'AQAB',
            'kid' => '2011-04-29',
            'kty' => 'RSA',
            'n' => $jwk->toArray()['n'],
        ]);
});

it('keeps members in canonical order regardless of input order', function (): void {
    $members = ecJwkMembers();
    $shuffled = ['y' => $members['y'], 'kty' => $members['kty'], 'x' => $members['x'], 'crv' => $members['crv']];

    expect(array_keys(Jwk::fromArray($shuffled)->toArray()))->toBe(['crv', 'kty', 'x', 'y']);
});

// ── optional members ────────────────────────────────────────────────────────

it('carries and drops optional members', function (): void {
    $jwk = Jwk::fromPublicKey(EcKey::generate());

    $decorated = $jwk->withKid('k1')->withUse('sig')->withAlg(Algorithm::ES256);

    expect($decorated->kid())->toBe('k1')
        ->and($decorated->use())->toBe('sig')
        ->and($decorated->alg())->toBe('ES256')
        ->and($decorated->withKid(null)->kid())->toBeNull()
        ->and($decorated->withUse(null)->use())->toBeNull()
        ->and($decorated->withAlg(null)->alg())->toBeNull();
});

it('refuses to write an alg that does not match the key', function (): void {
    $jwk = Jwk::fromPublicKey(EcKey::generate('P-256'));

    expect(fn (): Jwk => $jwk->withAlg(Algorithm::ES512))
        ->toThrow(MalformedJwkException::class, 'expected ES256');
});

it('refuses to write a non-signature use or an empty kid', function (): void {
    $jwk = Jwk::fromPublicKey(EcKey::generate());

    expect(fn (): Jwk => $jwk->withUse('enc'))->toThrow(MalformedJwkException::class, "only 'sig'")
        ->and(fn (): Jwk => $jwk->withKid(''))->toThrow(MalformedJwkException::class, 'must not be empty');
});

// ── strict parse: the negative matrix ───────────────────────────────────────

it('rejects an unknown or miscased key type', function (mixed $kty): void {
    $members = ecJwkMembers();
    $members['kty'] = $kty;

    expect(fn (): Jwk => Jwk::fromArray($members))
        ->toThrow(MalformedJwkException::class, 'not supported');
})->with(['ec', 'oct', 'RSA1_5', '', 1]);

it('rejects a JWK whose kty is missing or not a string', function (): void {
    $missing = ecJwkMembers();
    unset($missing['kty']);

    $structured = ecJwkMembers();
    $structured['kty'] = ['EC'];

    expect(fn (): Jwk => Jwk::fromArray($missing))->toThrow(MalformedJwkException::class, 'missing')
        ->and(fn (): Jwk => Jwk::fromArray($structured))->toThrow(MalformedJwkException::class, 'not supported');
});

it('rejects every private member and names what it found', function (string $member): void {
    $members = ecJwkMembers();
    $members[$member] = 'AAAA';

    expect(fn (): Jwk => Jwk::fromArray($members))
        ->toThrow(MalformedJwkException::class, "private member(s) \"{$member}\"");
})->with(['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k']);

it('rejects an unknown member rather than ignoring it', function (string $member): void {
    $members = ecJwkMembers();
    $members[$member] = 'smuggled';

    expect(fn (): Jwk => Jwk::fromArray($members))
        ->toThrow(MalformedJwkException::class, 'is not recognised');
})->with(['x5c', 'x5u', 'x5t', 'key_ops', 'ext']);

it('never lets one key type borrow another family members', function (): void {
    $ec = ecJwkMembers();
    $rsa = rsaJwkMembers();

    // kty RSA carrying EC members, and kty EC carrying RSA members.
    $confusedRsa = ['kty' => 'RSA', 'e' => $rsa['e'], 'n' => $rsa['n'], 'crv' => 'P-256', 'x' => $ec['x'], 'y' => $ec['y']];
    $confusedEc = ['kty' => 'EC', 'crv' => 'P-256', 'x' => $ec['x'], 'y' => $ec['y'], 'n' => $rsa['n'], 'e' => $rsa['e']];

    expect(fn (): Jwk => Jwk::fromArray($confusedRsa))->toThrow(MalformedJwkException::class, 'is not recognised')
        ->and(fn (): Jwk => Jwk::fromArray($confusedEc))->toThrow(MalformedJwkException::class, 'is not recognised');
});

it('rejects a missing required member', function (string $member): void {
    $members = ecJwkMembers();
    unset($members[$member]);

    expect(fn (): Jwk => Jwk::fromArray($members))
        ->toThrow(MalformedJwkException::class, "missing the required member \"{$member}\"");
})->with(['crv', 'x', 'y']);

it('rejects a missing required RSA member', function (string $member): void {
    $members = rsaJwkMembers();
    unset($members[$member]);

    expect(fn (): Jwk => Jwk::fromArray($members))
        ->toThrow(MalformedJwkException::class, 'missing the required member');
})->with(['n', 'e']);

it('rejects a non-string member', function (): void {
    $members = ecJwkMembers();
    $members['x'] = ['not', 'a', 'string'];

    expect(fn (): Jwk => Jwk::fromArray($members))
        ->toThrow(MalformedJwkException::class, 'must be a string');
});

it('rejects a member that is not strict base64url', function (string $value): void {
    $members = ecJwkMembers();
    $members['x'] = $value;

    expect(fn (): Jwk => Jwk::fromArray($members))
        ->toThrow(MalformedJwkException::class, 'not valid base64url');
})->with(['not base64!', 'AAAA+/==', '']);

it('checks the coordinate length against the STATED curve', function (): void {
    $p384 = ecJwkMembers('P-384');
    $p256 = ecJwkMembers('P-256');

    // A P-384 claim carrying P-256-length coordinates.
    $lying = ['kty' => 'EC', 'crv' => 'P-384', 'x' => $p256['x'], 'y' => $p256['y']];

    expect(fn (): Jwk => Jwk::fromArray($lying))
        ->toThrow(MalformedJwkException::class, 'must be exactly 48 bytes for P-384, got 32');

    // And the reverse: a P-256 claim carrying P-384-length coordinates.
    $lyingDown = ['kty' => 'EC', 'crv' => 'P-256', 'x' => $p384['x'], 'y' => $p384['y']];

    expect(fn (): Jwk => Jwk::fromArray($lyingDown))
        ->toThrow(MalformedJwkException::class, 'must be exactly 32 bytes for P-256, got 48');
});

it('rejects an unsupported curve', function (string $kty, string $crv): void {
    $members = $kty === 'EC' ? ecJwkMembers() : ['kty' => 'OKP', 'x' => Base64Url::encode(random_bytes(32))];
    $members['kty'] = $kty;
    $members['crv'] = $crv;

    expect(fn (): Jwk => Jwk::fromArray($members))
        ->toThrow(MalformedJwkException::class, 'is not supported');
})->with([
    ['EC', 'secp256k1'],
    ['EC', 'P-192'],
    ['OKP', 'X25519'],
    ['OKP', 'Ed448'],
]);

it('rejects an Ed25519 key of the wrong length', function (): void {
    $members = ['kty' => 'OKP', 'crv' => 'Ed25519', 'x' => Base64Url::encode(random_bytes(31))];

    expect(fn (): Jwk => Jwk::fromArray($members))
        ->toThrow(MalformedJwkException::class, 'must be exactly 32 bytes for Ed25519, got 31');
});

it('rejects a non-minimal RSA modulus or exponent', function (string $member): void {
    $members = rsaJwkMembers();
    $members[$member] = Base64Url::encode("\x00".Base64Url::decode($members[$member]));

    expect(fn (): Jwk => Jwk::fromArray($members))
        ->toThrow(MalformedJwkException::class, 'not a minimal big-endian integer');
})->with(['n', 'e']);

it('rejects an alg that contradicts the key type and curve', function (): void {
    $members = ecJwkMembers('P-256');
    $members['alg'] = 'ES512';

    expect(fn (): Jwk => Jwk::fromArray($members))
        ->toThrow(MalformedJwkException::class, 'expected ES256');
});

it('accepts every RS tier on an RSA JWK and pins the key to it', function (Algorithm $algorithm): void {
    $members = rsaJwkMembers();
    $members['alg'] = $algorithm->value;

    $jwk = Jwk::fromArray($members);
    $signature = (new Rs(RsaKey::private(keyPem('rsa-private')), $algorithm))->sign('payload');

    expect($jwk->alg())->toBe($algorithm->value)
        ->and($jwk->algorithm())->toBe($algorithm)
        ->and((new Rs($jwk->publicKey(), $jwk->algorithm()))->verify('payload', $signature))->toBeTrue()
        ->and(Jwk::fromPublicKey($jwk->publicKey())->withAlg($algorithm)->algorithm())->toBe($algorithm);
})->with([Algorithm::RS256, Algorithm::RS384, Algorithm::RS512]);

it('defaults an RSA JWK without alg to RS256', function (): void {
    $jwk = Jwk::fromArray(rsaJwkMembers());

    expect($jwk->algorithm())->toBe(Algorithm::RS256)
        ->and($jwk->withAlg(Algorithm::RS512)->withAlg(null)->algorithm())->toBe(Algorithm::RS256);
});

it('still rejects a non-RSA alg on an RSA JWK', function (string $alg): void {
    $members = rsaJwkMembers();
    $members['alg'] = $alg;

    expect(fn (): Jwk => Jwk::fromArray($members))
        ->toThrow(MalformedJwkException::class, 'expected RS256, RS384 or RS512')
        ->and(fn (): Jwk => Jwk::fromArray(rsaJwkMembers())->withAlg(Algorithm::tryFrom($alg) ?? Algorithm::ES256))
        ->toThrow(MalformedJwkException::class, 'expected RS256, RS384 or RS512');
})->with(['ES256', 'HS256', 'PS256', 'none']);

it('rejects a non-signature use and an empty kid on parse', function (): void {
    $withUse = ecJwkMembers();
    $withUse['use'] = 'enc';

    $withKid = ecJwkMembers();
    $withKid['kid'] = '';

    expect(fn (): Jwk => Jwk::fromArray($withUse))->toThrow(MalformedJwkException::class, "only 'sig'")
        ->and(fn (): Jwk => Jwk::fromArray($withKid))->toThrow(MalformedJwkException::class, 'must not be empty');
});

it('accepts an alg and use that agree with the key', function (): void {
    $members = ecJwkMembers('P-384');
    $members['alg'] = 'ES384';
    $members['use'] = 'sig';
    $members['kid'] = 'k9';

    $jwk = Jwk::fromArray($members);

    expect($jwk->alg())->toBe('ES384')
        ->and($jwk->use())->toBe('sig')
        ->and($jwk->kid())->toBe('k9');
});

// ── DoS caps ────────────────────────────────────────────────────────────────

it('rejects an oversized member before decoding it', function (): void {
    $members = ecJwkMembers();
    $members['x'] = str_repeat('A', Jwk::MAX_MEMBER_BYTES + 1);

    expect(fn (): Jwk => Jwk::fromArray($members))
        ->toThrow(MalformedJwkException::class, 'over the '.Jwk::MAX_MEMBER_BYTES.'-byte cap');
});

it('rejects an oversized JSON document before decoding it', function (): void {
    $json = '{"kty":"EC","x":"'.str_repeat('A', Jwk::MAX_JSON_BYTES).'"}';

    expect(fn (): Jwk => Jwk::fromJson($json))
        ->toThrow(MalformedJwkException::class, 'over the '.Jwk::MAX_JSON_BYTES.'-byte cap');
});

it('rejects malformed JSON and a JSON document that is not an object', function (string $json): void {
    expect(fn (): Jwk => Jwk::fromJson($json))->toThrow(MalformedJwkException::class);
})->with(['{', '"a string"', '42', 'null', '[]', '{"kty":{"a":{"b":{"c":1}}}}']);

// ── documented behaviours ───────────────────────────────────────────────────

it('keeps the last of a duplicated JSON member', function (): void {
    $members = ecJwkMembers();
    $other = ecJwkMembers();

    $json = sprintf(
        '{"kty":"EC","crv":"P-256","y":"%s","x":"%s","x":"%s"}',
        $members['y'],
        $other['x'],
        $members['x'],
    );

    // Documented limitation: json_decode keeps the LAST occurrence. It cannot
    // mislead us — the thumbprint is over the members we kept and validated.
    expect(Jwk::fromJson($json)->toArray()['x'])->toBe($members['x']);
});

it('applies the package key policy when the JWK becomes a key', function (): void {
    $weak = RsaKey::public(keyPem('rsa-public'));
    $members = Jwk::fromPublicKey($weak)->toArray();

    // A 1024-bit modulus: parseable as a JWK, refused as a key.
    $members['n'] = Base64Url::encode(random_bytes(128));
    $members['e'] = 'AQAB';

    $jwk = Jwk::fromArray($members);

    expect($jwk->keyType())->toBe(JwkKeyType::Rsa)
        ->and(fn (): PublicKey => $jwk->publicKey())->toThrow(WeakKeyException::class);
});

it('never verifies a signature with an off-curve point', function (): void {
    $key = EcKey::generate();
    $members = Jwk::fromPublicKey($key)->toArray();

    // Flip the last byte of x: the point is almost certainly no longer on P-256.
    $x = Base64Url::decode($members['x']);
    $x[31] = chr(ord($x[31]) ^ 0xFF);
    $members['x'] = Base64Url::encode($x);

    $jwk = Jwk::fromArray($members);
    $signature = $key->verifier()->sign('payload');

    try {
        $rogue = $jwk->publicKey();
    } catch (KeyLoadException) {
        // OpenSSL refused the point outright — the strongest outcome.
        expect(true)->toBeTrue();

        return;
    }

    // Otherwise it must be a key that can never verify the genuine signature.
    expect($rogue->verifier()->verify('payload', $signature))->toBeFalse();
});
