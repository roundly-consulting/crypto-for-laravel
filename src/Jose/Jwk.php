<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Jose;

use JsonException;
use JsonSerializable;
use RoundlyConsulting\Crypto\Codec\Base64Url;
use RoundlyConsulting\Crypto\Codec\InvalidEncodingException;
use RoundlyConsulting\Crypto\Hash\Digest;
use RoundlyConsulting\Crypto\Hash\HashAlgorithm;
use RoundlyConsulting\Crypto\Signature\Algorithm;
use RoundlyConsulting\Crypto\Signature\Key\EcKey;
use RoundlyConsulting\Crypto\Signature\Key\OkpKey;
use RoundlyConsulting\Crypto\Signature\Key\PublicKey;
use RoundlyConsulting\Crypto\Signature\Key\RsaKey;
use SensitiveParameter;

/**
 * An RFC 7517 public JWK, plus its RFC 7638 thumbprint.
 *
 * Public keys only. A JWK carrying private members is rejected on parse, so an
 * attacker-supplied document can never smuggle in a key this package would sign
 * with, and a parsed JWK only ever yields a verification key.
 *
 * Parsing is deliberately strict — stricter than RFC 7517 §4, which says unknown
 * members *should* be ignored. This package rejects them: its callers round-trip
 * documents this fleet mints, so an unknown member is either a bug or an attacker
 * probing for a parser differential (an `x5c` smuggled past us, a member another
 * parser honours and we silently drop). Relaxing it later is a per-member
 * decision; un-shipping a silently-carried member is not.
 *
 * The thumbprint is computed from this object's canonical re-serialization of the
 * *validated* members — never from the input bytes — so a duplicate-carrying or
 * oddly-ordered document can never make us authorize one key while displaying
 * another.
 */
final readonly class Jwk implements JsonSerializable
{
    /** A `fromJson` input cap. A real JWK is well under 2 KiB; this is checked before json_decode. */
    public const int MAX_JSON_BYTES = 16384;

    /** A per-member cap, checked BEFORE any base64url decode, so an oversized `n` is never decoded. */
    public const int MAX_MEMBER_BYTES = 8192;

    /** RFC 7638 §3.2: the required members per key type, in lexicographic order. These, and only these, are thumbprinted. */
    private const array REQUIRED_MEMBERS = [
        'EC' => ['crv', 'kty', 'x', 'y'],
        'RSA' => ['e', 'kty', 'n'],
        'OKP' => ['crv', 'kty', 'x'],
    ];

    /** Members that may accompany the required set. Anything else is rejected. */
    private const array OPTIONAL_MEMBERS = ['alg', 'kid', 'use'];

    /** Private (and symmetric) members — RFC 7518 §6.2.2/§6.3.2/§6.4, RFC 8037 §2. Never accepted. */
    private const array PRIVATE_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'];

    /** Members whose value is base64url-encoded raw bytes. */
    private const array BINARY_MEMBERS = ['x', 'y', 'n', 'e'];

    /** EC curve → the exact coordinate length its `x` and `y` must decode to. */
    private const array EC_CURVES = ['P-256' => 32, 'P-384' => 48, 'P-521' => 66];

    /** RFC 8037 §2: the only OKP curve, and its public-key length. */
    private const string OKP_CURVE = 'Ed25519';

    private const int OKP_BYTES = 32;

    /**
     * @param  array<string, string>  $members  validated, lexicographically ordered
     */
    private function __construct(
        private JwkKeyType $keyType,
        private array $members,
    ) {}

    // ── key → JWK ───────────────────────────────────────────────────────────

    /**
     * Serialize a public key as a JWK. The curve label and the coordinate padding
     * come from the key itself, so a P-384 key is never described as a P-256 one.
     *
     * @throws MalformedJwkException|\RoundlyConsulting\Crypto\Signature\KeyLoadException
     */
    public static function fromPublicKey(PublicKey $key): self
    {
        $members = match (true) {
            $key instanceof EcKey => self::ecMembers($key),
            $key instanceof RsaKey => self::rsaMembers($key),
            $key instanceof OkpKey => self::okpMembers($key),
            default => throw MalformedJwkException::unsupportedKeyType($key::class),
        };

        ksort($members, SORT_STRING);

        return new self(JwkKeyType::from($members['kty']), $members);
    }

    // ── JWK → key ───────────────────────────────────────────────────────────

    /**
     * Parse a JWK from its decoded members. See the class docblock for why the
     * parse is strict.
     *
     * The input is `#[SensitiveParameter]`: a private key handed over by mistake
     * stays out of the trace of the exception that refuses it.
     *
     * @param  array<array-key, mixed>  $members
     *
     * @throws MalformedJwkException
     */
    public static function fromArray(#[SensitiveParameter] array $members): self
    {
        self::assertMembersWithinCap($members);

        $keyType = self::readKeyType($members);

        self::rejectPrivateMembers($members);
        self::rejectUnknownMembers($members, $keyType);

        $strings = self::readStringMembers($members, $keyType);

        self::assertValueShape($strings, $keyType);

        ksort($strings, SORT_STRING);

        $jwk = new self($keyType, $strings);

        self::assertOptionalMembers($jwk, $strings);

        return $jwk;
    }

    /**
     * Parse a JWK from a JSON document.
     *
     * Duplicate members are a documented limitation: `json_decode` keeps the LAST
     * occurrence. That cannot mislead this package — the thumbprint is derived
     * from the validated members it kept, not from the raw bytes.
     *
     * @throws MalformedJwkException
     */
    public static function fromJson(#[SensitiveParameter] string $json): self
    {
        $bytes = strlen($json);

        if ($bytes > self::MAX_JSON_BYTES) {
            throw MalformedJwkException::tooLarge($bytes, self::MAX_JSON_BYTES);
        }

        try {
            $decoded = json_decode($json, true, 4, JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw MalformedJwkException::malformedJson($exception->getMessage());
        }

        if (! is_array($decoded)) {
            throw MalformedJwkException::malformedJson('the document is not a JSON object');
        }

        return self::fromArray($decoded);
    }

    /**
     * The public key this JWK describes — the inverse of {@see fromPublicKey()}.
     *
     * The package's own key policy applies here (RSA ≥ 2048 bits with a sane
     * exponent, a supported curve), so a third-party JWK cannot hand us a key we
     * would refuse to load from PEM.
     *
     * @throws MalformedJwkException|\RoundlyConsulting\Crypto\Signature\KeyLoadException|\RoundlyConsulting\Crypto\Signature\WeakKeyException
     */
    public function publicKey(): PublicKey
    {
        return match ($this->keyType) {
            JwkKeyType::Ec => EcKey::fromCoordinates(
                self::decode('x', $this->members['x']),
                self::decode('y', $this->members['y']),
                $this->members['crv'],
            ),
            JwkKeyType::Rsa => RsaKey::fromModulusExponent(
                self::decode('n', $this->members['n']),
                self::decode('e', $this->members['e']),
            ),
            JwkKeyType::Okp => OkpKey::ed25519(self::decode('x', $this->members['x'])),
        };
    }

    // ── members ─────────────────────────────────────────────────────────────

    public function keyType(): JwkKeyType
    {
        return $this->keyType;
    }

    /**
     * The signature algorithm this key is pinned to.
     *
     * EC and OKP keys: derived from `kty` + `crv` — the curve fixes the algorithm,
     * so the `alg` member can only agree with it. RSA keys fit every RS* tier, so
     * there the (validated) `alg` names the tier — RS256, RS384 or RS512, never an
     * algorithm of another family — and an RSA JWK without one is RS256. Build the
     * verifier with it: `new Rs($jwk->publicKey(), $jwk->algorithm())`.
     */
    public function algorithm(): Algorithm
    {
        return match ($this->keyType) {
            JwkKeyType::Rsa => Algorithm::from($this->members['alg'] ?? Algorithm::RS256->value),
            default => $this->admissibleAlgorithms()[0],
        };
    }

    public function kid(): ?string
    {
        return $this->members['kid'] ?? null;
    }

    public function alg(): ?string
    {
        return $this->members['alg'] ?? null;
    }

    public function use(): ?string
    {
        return $this->members['use'] ?? null;
    }

    /**
     * A copy carrying (or dropping) a `kid`. Optional members are never
     * thumbprinted, so this cannot change {@see thumbprint()}.
     *
     * @throws MalformedJwkException when the kid is an empty string
     */
    public function withKid(?string $kid): self
    {
        if ($kid === '') {
            throw MalformedJwkException::invalidMember('kid', 'must not be empty');
        }

        return $this->withOptional('kid', $kid);
    }

    /**
     * @throws MalformedJwkException when the algorithm is not one this key admits (the curve's for EC/OKP, an RS* tier for RSA)
     */
    public function withAlg(?Algorithm $alg): self
    {
        if ($alg !== null) {
            $this->assertAdmissible($alg->value);
        }

        return $this->withOptional('alg', $alg?->value);
    }

    /**
     * @throws MalformedJwkException when the use is anything but `sig`
     */
    public function withUse(?string $use): self
    {
        if ($use !== null && $use !== 'sig') {
            throw MalformedJwkException::invalidMember('use', "is [{$use}]; only 'sig' keys are usable here");
        }

        return $this->withOptional('use', $use);
    }

    /**
     * Every member, lexicographically ordered.
     *
     * @return array<string, string>
     */
    public function toArray(): array
    {
        return $this->members;
    }

    /**
     * @return array<string, string>
     */
    public function jsonSerialize(): array
    {
        return $this->members;
    }

    // ── RFC 7638 ────────────────────────────────────────────────────────────

    /**
     * The RFC 7638 thumbprint: base64url of the digest of the canonical JSON of
     * the required members.
     *
     * This value feeds ACME key authorizations (RFC 8555 §8.1). A one-byte
     * deviation breaks certificate issuance, which is why the canonical form is
     * pinned by frozen vectors rather than trusted to a JSON encoder's defaults.
     */
    public function thumbprint(HashAlgorithm $algorithm = HashAlgorithm::Sha256): string
    {
        return Base64Url::encode($this->thumbprintRaw($algorithm));
    }

    /**
     * The raw digest bytes of the same canonical form.
     */
    public function thumbprintRaw(HashAlgorithm $algorithm = HashAlgorithm::Sha256): string
    {
        return (new Digest($algorithm))->raw($this->canonical());
    }

    /**
     * The RFC 7638 §3.2 required-members subset, lexicographically ordered.
     *
     * @return array<string, string>
     */
    public function requiredMembers(): array
    {
        $required = [];

        foreach (self::REQUIRED_MEMBERS[$this->keyType->value] as $member) {
            $required[$member] = $this->members[$member];
        }

        ksort($required, SORT_STRING);

        return $required;
    }

    /**
     * The exact bytes RFC 7638 §3.3 hashes: required members only, sorted by
     * member name, no whitespace, slashes unescaped.
     */
    private function canonical(): string
    {
        return json_encode($this->requiredMembers(), JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    }

    // ── construction from keys ──────────────────────────────────────────────

    /**
     * @return array<string, string>
     *
     * @throws \RoundlyConsulting\Crypto\Signature\KeyLoadException
     */
    private static function ecMembers(EcKey $key): array
    {
        $coordinates = $key->coordinates();

        return [
            'crv' => $key->curve,
            'kty' => JwkKeyType::Ec->value,
            'x' => Base64Url::encode($coordinates->x),
            'y' => Base64Url::encode($coordinates->y),
        ];
    }

    /**
     * @return array<string, string>
     *
     * @throws \RoundlyConsulting\Crypto\Signature\KeyLoadException
     */
    private static function rsaMembers(RsaKey $key): array
    {
        return [
            'e' => Base64Url::encode($key->exponent()),
            'kty' => JwkKeyType::Rsa->value,
            'n' => Base64Url::encode($key->modulus()),
        ];
    }

    /**
     * @return array<string, string>
     */
    private static function okpMembers(OkpKey $key): array
    {
        return [
            'crv' => self::OKP_CURVE,
            'kty' => JwkKeyType::Okp->value,
            'x' => Base64Url::encode($key->publicKey),
        ];
    }

    // ── strict parsing ──────────────────────────────────────────────────────

    /**
     * Size first, so an attacker never gets us to decode a multi-megabyte member.
     *
     * @param  array<array-key, mixed>  $members
     *
     * @throws MalformedJwkException
     */
    private static function assertMembersWithinCap(#[SensitiveParameter] array $members): void
    {
        foreach ($members as $value) {
            if (is_string($value) && strlen($value) > self::MAX_MEMBER_BYTES) {
                throw MalformedJwkException::tooLarge(strlen($value), self::MAX_MEMBER_BYTES);
            }
        }
    }

    /**
     * @param  array<array-key, mixed>  $members
     *
     * @throws MalformedJwkException
     */
    private static function readKeyType(#[SensitiveParameter] array $members): JwkKeyType
    {
        $kty = $members['kty'] ?? null;

        if (! is_string($kty)) {
            throw MalformedJwkException::unsupportedKeyType(is_scalar($kty) ? (string) $kty : 'missing');
        }

        return JwkKeyType::tryFrom($kty) ?? throw MalformedJwkException::unsupportedKeyType($kty);
    }

    /**
     * @param  array<array-key, mixed>  $members
     *
     * @throws MalformedJwkException
     */
    private static function rejectPrivateMembers(#[SensitiveParameter] array $members): void
    {
        $found = array_values(array_intersect(self::PRIVATE_MEMBERS, array_map(strval(...), array_keys($members))));

        if ($found !== []) {
            throw MalformedJwkException::privateMembersRejected($found);
        }
    }

    /**
     * The whitelist is per key type, so a `kty` can never borrow another family's
     * members: `n` on an EC key is as unknown as `x5c` is.
     *
     * @param  array<array-key, mixed>  $members
     *
     * @throws MalformedJwkException
     */
    private static function rejectUnknownMembers(array $members, JwkKeyType $keyType): void
    {
        $allowed = [...self::REQUIRED_MEMBERS[$keyType->value], ...self::OPTIONAL_MEMBERS];

        foreach (array_keys($members) as $member) {
            if (! in_array((string) $member, $allowed, true)) {
                throw MalformedJwkException::unknownMember((string) $member);
            }
        }
    }

    /**
     * @param  array<array-key, mixed>  $members
     * @return array<string, string>
     *
     * @throws MalformedJwkException
     */
    private static function readStringMembers(array $members, JwkKeyType $keyType): array
    {
        $strings = [];

        foreach (self::REQUIRED_MEMBERS[$keyType->value] as $member) {
            if (! array_key_exists($member, $members)) {
                throw MalformedJwkException::missingMember($member);
            }
        }

        foreach ($members as $member => $value) {
            if (! is_string($value)) {
                throw MalformedJwkException::invalidMember((string) $member, 'must be a string');
            }

            $strings[(string) $member] = $value;
        }

        return $strings;
    }

    /**
     * Values are checked against the STATED `crv`, before any key is built: a
     * P-384 claim with 32-byte coordinates is a lie, not something to repad.
     *
     * @param  array<string, string>  $members
     *
     * @throws MalformedJwkException
     */
    private static function assertValueShape(array $members, JwkKeyType $keyType): void
    {
        foreach (self::BINARY_MEMBERS as $member) {
            if (isset($members[$member])) {
                self::decode($member, $members[$member]);
            }
        }

        match ($keyType) {
            JwkKeyType::Ec => self::assertEcShape($members),
            JwkKeyType::Okp => self::assertOkpShape($members),
            JwkKeyType::Rsa => self::assertRsaShape($members),
        };
    }

    /**
     * @param  array<string, string>  $members
     *
     * @throws MalformedJwkException
     */
    private static function assertEcShape(array $members): void
    {
        $curve = $members['crv'];
        $length = self::EC_CURVES[$curve] ?? throw MalformedJwkException::unsupportedCurve($curve);

        foreach (['x', 'y'] as $member) {
            $actual = strlen(self::decode($member, $members[$member]));

            if ($actual !== $length) {
                throw MalformedJwkException::invalidMember(
                    $member,
                    "must be exactly {$length} bytes for {$curve}, got {$actual}",
                );
            }
        }
    }

    /**
     * @param  array<string, string>  $members
     *
     * @throws MalformedJwkException
     */
    private static function assertOkpShape(array $members): void
    {
        if ($members['crv'] !== self::OKP_CURVE) {
            throw MalformedJwkException::unsupportedCurve($members['crv']);
        }

        $actual = strlen(self::decode('x', $members['x']));

        if ($actual !== self::OKP_BYTES) {
            throw MalformedJwkException::invalidMember('x', 'must be exactly '.self::OKP_BYTES." bytes for Ed25519, got {$actual}");
        }
    }

    /**
     * RFC 7518 §6.3.1 requires the minimal big-endian encoding. A non-minimal `n`
     * is rejected rather than normalized: two byte-different documents for the
     * same key would otherwise thumbprint differently — exactly the ambiguity
     * RFC 7638 exists to kill.
     *
     * @param  array<string, string>  $members
     *
     * @throws MalformedJwkException
     */
    private static function assertRsaShape(array $members): void
    {
        foreach (['n', 'e'] as $member) {
            // An empty member cannot reach here: strict base64url rejects the
            // empty string, so a decoded value always has at least one byte.
            $bytes = self::decode($member, $members[$member]);

            if ($bytes[0] === "\x00") {
                throw MalformedJwkException::invalidMember($member, 'is not a minimal big-endian integer (it has a leading zero octet)');
            }
        }
    }

    /**
     * `kid`, `alg` and `use` are optional, but not free-form: an `alg` that does
     * not match the key, or a `use` other than `sig`, is a lie a later consumer
     * might honour.
     *
     * @param  array<string, string>  $members
     *
     * @throws MalformedJwkException
     */
    private static function assertOptionalMembers(self $jwk, array $members): void
    {
        if (isset($members['kid']) && $members['kid'] === '') {
            throw MalformedJwkException::invalidMember('kid', 'must not be empty');
        }

        if (isset($members['alg'])) {
            $jwk->assertAdmissible($members['alg']);
        }

        if (isset($members['use']) && $members['use'] !== 'sig') {
            throw MalformedJwkException::invalidMember('use', "is [{$members['use']}]; only 'sig' keys are usable here");
        }
    }

    /**
     * The algorithms this key may be used with: every RS* tier for RSA, and the
     * one algorithm the curve implies for EC and OKP.
     *
     * @return non-empty-list<Algorithm>
     */
    private function admissibleAlgorithms(): array
    {
        return match ($this->keyType) {
            JwkKeyType::Rsa => [Algorithm::RS256, Algorithm::RS384, Algorithm::RS512],
            JwkKeyType::Okp => [Algorithm::EdDSA],
            JwkKeyType::Ec => [match ($this->members['crv']) {
                'P-384' => Algorithm::ES384,
                'P-521' => Algorithm::ES512,
                default => Algorithm::ES256,
            }],
        };
    }

    /**
     * @throws MalformedJwkException when the algorithm is not one this key admits
     */
    private function assertAdmissible(string $alg): void
    {
        $admissible = $this->admissibleAlgorithms();

        if (in_array(Algorithm::tryFrom($alg), $admissible, true)) {
            return;
        }

        $names = array_map(static fn (Algorithm $algorithm): string => $algorithm->value, $admissible);
        $last = array_pop($names);
        $expected = $names === [] ? $last : implode(', ', $names).' or '.$last;

        throw MalformedJwkException::invalidMember('alg', "is {$alg}, which does not match this key (expected {$expected})");
    }

    /**
     * @throws MalformedJwkException when the member is not strict base64url
     */
    private static function decode(string $member, string $value): string
    {
        try {
            return Base64Url::decode($value);
        } catch (InvalidEncodingException) {
            throw MalformedJwkException::invalidMember($member, 'is not valid base64url');
        }
    }

    private function withOptional(string $member, ?string $value): self
    {
        $members = $this->members;

        if ($value === null) {
            unset($members[$member]);
        } else {
            $members[$member] = $value;
        }

        ksort($members, SORT_STRING);

        return new self($this->keyType, $members);
    }
}
