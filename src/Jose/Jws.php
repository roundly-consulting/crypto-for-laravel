<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Jose;

use JsonException;
use RoundlyConsulting\Crypto\Codec\Base64Url;
use RoundlyConsulting\Crypto\Codec\InvalidEncodingException;
use RoundlyConsulting\Crypto\Signature\Algorithm;
use RoundlyConsulting\Crypto\Signature\AlgorithmMismatchException;
use RoundlyConsulting\Crypto\Signature\Signer;
use RoundlyConsulting\Crypto\Signature\Verifier;

/**
 * Compact and flattened JSON Web Signature (RFC 7515).
 *
 * Verification is deliberately narrow and strict: structure, a length cap, a
 * pre-signature algorithm pin, `crit` rejection, and the signature — nothing
 * else. It never selects the key or algorithm from the token header, so
 * `alg:none` downgrades and RS256↔HS256 confusion are structurally impossible.
 * Temporal (`exp`/`nbf`/`iat`) validation is opt-in via
 * {@see Claims::assertTemporal()}, and claim policy stays with the caller.
 */
final class Jws
{
    /**
     * Upper bound on a compact JWS we will even attempt to decode. RS256 tokens
     * with a full claim set stay well under 2 KB; 8 KB leaves generous headroom
     * while capping decode effort.
     */
    public const int MAX_ENCODED_BYTES = 8192;

    /**
     * Sign a compact JWS (`header.payload.signature`). The header always carries
     * `typ: JWT` and the signer's `alg`; JSON is encoded deterministically so
     * byte-for-byte parity fixtures reproduce exactly.
     *
     * @param  array<string, mixed>  $header  extra protected-header entries (e.g. `kid`)
     * @param  array<string, mixed>  $payload
     *
     * @throws MalformedTokenException when a value cannot be encoded to JSON
     */
    public function sign(array $header, array $payload, Signer $signer): string
    {
        $header = ['typ' => 'JWT', ...$header, 'alg' => $signer->algorithm()->value];

        $segments = [
            Base64Url::encode($this->json($header)),
            Base64Url::encode($this->json($payload)),
        ];

        $segments[] = Base64Url::encode($signer->sign(implode('.', $segments)));

        return implode('.', $segments);
    }

    /**
     * Verify a compact JWS and return its {@see Claims}. The header `alg` must
     * string-equal $expected AND match the verifier's algorithm, both checked
     * before the signature is examined.
     *
     * @throws MalformedTokenException|AlgorithmMismatchException|InvalidEncodingException
     * @throws \RoundlyConsulting\Crypto\Signature\InvalidSignatureException
     */
    public function verify(string $compact, Verifier $verifier, Algorithm $expected): Claims
    {
        if ($verifier->algorithm() !== $expected) {
            throw AlgorithmMismatchException::keyForAlgorithm($expected);
        }

        if (strlen($compact) > self::MAX_ENCODED_BYTES) {
            throw MalformedTokenException::make('The token exceeds the maximum permitted length.');
        }

        $parts = explode('.', $compact);

        if (count($parts) !== 3) {
            throw MalformedTokenException::make('A compact JWS must have exactly three segments.');
        }

        [$headerSegment, $payloadSegment, $signatureSegment] = $parts;

        $header = $this->decodeJsonObject(Base64Url::decode($headerSegment), 'header');

        if (array_key_exists('crit', $header)) {
            throw MalformedTokenException::make('The `crit` header is not supported.');
        }

        $alg = $header['alg'] ?? null;

        // Pin the algorithm before touching the signature so an `alg:none`
        // downgrade is rejected here. Strict string equality — never a
        // case-insensitive or type-juggling compare.
        if (! is_string($alg) || $alg !== $expected->value) {
            throw AlgorithmMismatchException::pinning();
        }

        $payload = $this->decodeJsonObject(Base64Url::decode($payloadSegment), 'payload');
        $signature = Base64Url::decode($signatureSegment);

        if (! $verifier->verify($headerSegment.'.'.$payloadSegment, $signature)) {
            throw \RoundlyConsulting\Crypto\Signature\InvalidSignatureException::make();
        }

        return new Claims($payload);
    }

    /**
     * Sign a flattened-JSON JWS (RFC 7515 §7.2.2), as ACME uses. The `alg` is
     * merged into the protected header; an empty payload encodes to an empty
     * segment (ACME POST-as-GET).
     *
     * @param  array<string, mixed>  $protected
     *
     * @throws MalformedTokenException when a value cannot be encoded to JSON
     */
    public function flattened(array $protected, string $payload, Signer $signer): FlattenedJws
    {
        $protected = [...$protected, 'alg' => $signer->algorithm()->value];

        $encodedProtected = Base64Url::encode($this->json($protected));
        $encodedPayload = $payload === '' ? '' : Base64Url::encode($payload);

        $signature = $signer->sign($encodedProtected.'.'.$encodedPayload);

        return new FlattenedJws(
            protected: $encodedProtected,
            payload: $encodedPayload,
            signature: Base64Url::encode($signature),
        );
    }

    /**
     * @param  array<string, mixed>  $data
     *
     * @throws MalformedTokenException
     */
    private function json(array $data): string
    {
        try {
            // JSON_UNESCAPED_SLASHES keeps byte output identical to reference
            // encoders so pre-captured parity fixtures reproduce exactly.
            return json_encode($data, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new MalformedTokenException('A value could not be encoded to JSON.', previous: $e);
        }
    }

    /**
     * @return array<string, mixed>
     *
     * @throws MalformedTokenException
     */
    private function decodeJsonObject(string $json, string $part): array
    {
        try {
            $decoded = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            throw MalformedTokenException::make("The token {$part} is not valid JSON.");
        }

        if (! is_array($decoded) || (array_is_list($decoded) && $decoded !== [])) {
            throw MalformedTokenException::make("The token {$part} must be a JSON object.");
        }

        /** @var array<string, mixed> $decoded */
        return $decoded;
    }
}
