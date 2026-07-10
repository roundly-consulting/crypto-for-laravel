<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Jose;

use JsonSerializable;

/**
 * A flattened JWS JSON serialization (RFC 7515 §7.2.2), as used by ACME: the
 * base64url `protected` header, the base64url `payload`, and the base64url
 * `signature`.
 */
final readonly class FlattenedJws implements JsonSerializable
{
    public function __construct(
        public string $protected,
        public string $payload,
        public string $signature,
    ) {}

    /**
     * The on-the-wire JWS JSON object.
     *
     * @return array{protected: string, payload: string, signature: string}
     */
    public function jsonSerialize(): array
    {
        return [
            'protected' => $this->protected,
            'payload' => $this->payload,
            'signature' => $this->signature,
        ];
    }
}
