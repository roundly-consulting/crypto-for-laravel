<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Cose;

use RoundlyConsulting\Crypto\Signature\Key\PublicKey;

/**
 * The parsed WebAuthn authenticatorData byte structure (spec §6.1):
 * 32-byte rpIdHash, 1 flag byte, 4-byte big-endian sign counter, and — when the
 * AT flag is set — attested credential data (16-byte AAGUID, 2-byte credential
 * id length, credential id, and the length-delimited COSE public key).
 *
 * WebAuthn-shaped, but purely structural: it decodes bytes and never applies
 * ceremony policy (origin, challenge, rpId, sign-count reconciliation) — that
 * stays with the relying party.
 */
final readonly class AuthenticatorData
{
    private function __construct(
        public string $rpIdHash,
        public AuthenticatorFlags $flags,
        public int $signCount,
        public ?string $aaguid = null,
        public ?string $credentialId = null,
        public ?PublicKey $coseKey = null,
        public ?string $coseKeyBytes = null,
    ) {}

    /**
     * @throws MalformedCborException|UnsupportedAlgorithmException
     */
    public static function parse(string $bytes): self
    {
        if (strlen($bytes) < 37) {
            throw MalformedCborException::make('authenticator data is too short');
        }

        $rpIdHash = substr($bytes, 0, 32);
        $flags = AuthenticatorFlags::fromByte(ord($bytes[32]));

        $signCount = unpack('N', substr($bytes, 33, 4));

        if ($signCount === false) {
            throw MalformedCborException::make('unreadable sign counter');
        }

        $offset = 37;

        if (! $flags->attestedCredentialData) {
            self::assertNoTrailingData($bytes, $offset, $flags->extensionData);

            return new self($rpIdHash, $flags, (int) $signCount[1]);
        }

        return self::parseAttested($bytes, $offset, $rpIdHash, $flags, (int) $signCount[1]);
    }

    /**
     * @throws MalformedCborException|UnsupportedAlgorithmException
     */
    private static function parseAttested(
        string $bytes,
        int $offset,
        string $rpIdHash,
        AuthenticatorFlags $flags,
        int $signCount,
    ): self {
        if ($offset + 18 > strlen($bytes)) {
            throw MalformedCborException::make('attested credential data is missing');
        }

        $aaguid = substr($bytes, $offset, 16);
        $offset += 16;

        $lengthBytes = unpack('n', substr($bytes, $offset, 2));

        if ($lengthBytes === false) {
            throw MalformedCborException::make('unreadable credential id length');
        }

        $credentialIdLength = (int) $lengthBytes[1];
        $offset += 2;

        if ($credentialIdLength < 1 || $offset + $credentialIdLength > strlen($bytes)) {
            throw MalformedCborException::make('credential id length exceeds remaining input');
        }

        $credentialId = substr($bytes, $offset, $credentialIdLength);
        $offset += $credentialIdLength;

        // The COSE key is length-delimited; decodeFirst reports how far it ran so
        // any trailing extension map can be located and validated.
        $result = (new CborDecoder)->decodeFirst(substr($bytes, $offset));

        if (! is_array($result->value)) {
            throw MalformedCborException::make('COSE key is not a map');
        }

        $coseKeyBytes = substr($bytes, $offset, $result->bytesConsumed);
        $offset += $result->bytesConsumed;

        self::assertNoTrailingData($bytes, $offset, $flags->extensionData);

        return new self(
            rpIdHash: $rpIdHash,
            flags: $flags,
            signCount: $signCount,
            aaguid: $aaguid,
            credentialId: $credentialId,
            coseKey: CoseKey::fromCbor($coseKeyBytes),
            coseKeyBytes: $coseKeyBytes,
        );
    }

    /**
     * Extensions are ignored, but the structure must still terminate cleanly:
     * exactly one CBOR extension map when ED is set, and nothing otherwise.
     *
     * @throws MalformedCborException
     */
    private static function assertNoTrailingData(string $bytes, int $offset, bool $extensionData): void
    {
        $remaining = strlen($bytes) - $offset;

        if (! $extensionData) {
            if ($remaining !== 0) {
                throw MalformedCborException::make('unexpected trailing bytes');
            }

            return;
        }

        if ($remaining < 1) {
            throw MalformedCborException::make('extension data flag set but no extensions present');
        }

        $result = (new CborDecoder)->decodeFirst(substr($bytes, $offset));

        if (! is_array($result->value) || $result->bytesConsumed !== $remaining) {
            throw MalformedCborException::make('malformed extension data');
        }
    }
}
