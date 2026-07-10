<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Cose\AuthenticatorData;
use RoundlyConsulting\Crypto\Cose\AuthenticatorFlags;
use RoundlyConsulting\Crypto\Cose\MalformedCborException;
use RoundlyConsulting\Crypto\Signature\Algorithm;

it('parses attested authenticator data with a COSE key', function (): void {
    $vector = cryptoVectors()['auth_data'];
    $parsed = AuthenticatorData::parse(hex2bin($vector['bytes']));

    expect(bin2hex($parsed->rpIdHash))->toBe($vector['rp_id_hash'])
        ->and($parsed->signCount)->toBe($vector['sign_count'])
        ->and($parsed->flags->userPresent)->toBeTrue()
        ->and($parsed->flags->userVerified)->toBeTrue()
        ->and($parsed->flags->attestedCredentialData)->toBeTrue()
        ->and(bin2hex((string) $parsed->credentialId))->toBe($vector['credential_id'])
        ->and($parsed->coseKey?->algorithm())->toBe(Algorithm::ES256)
        ->and($parsed->coseKeyBytes)->not->toBeNull();
});

it('parses assertion authenticator data without attested data', function (): void {
    $vector = cryptoVectors()['auth_data_assertion'];
    $parsed = AuthenticatorData::parse(hex2bin($vector['bytes']));

    expect($parsed->signCount)->toBe($vector['sign_count'])
        ->and($parsed->flags->attestedCredentialData)->toBeFalse()
        ->and($parsed->coseKey)->toBeNull()
        ->and($parsed->aaguid)->toBeNull();
});

it('reads a high sign counter as an unsigned 32-bit integer', function (): void {
    // A counter with the top bit set (0xFFFFFFFF) must decode to 4_294_967_295,
    // never a negative value — the counter is unsigned. Requires 64-bit PHP.
    $bytes = str_repeat("\x00", 32).chr(0x05)."\xFF\xFF\xFF\xFF";
    $parsed = AuthenticatorData::parse($bytes);

    expect($parsed->signCount)->toBe(4_294_967_295)
        ->and($parsed->signCount)->toBeGreaterThan(0);
});

it('rejects authenticator data that is too short', function (): void {
    AuthenticatorData::parse(str_repeat("\x00", 10));
})->throws(MalformedCborException::class);

it('rejects trailing bytes when no extension flag is set', function (): void {
    $vector = cryptoVectors()['auth_data_assertion'];

    AuthenticatorData::parse(hex2bin($vector['bytes'])."\xff");
})->throws(MalformedCborException::class);

it('rejects attested data that is truncated', function (): void {
    $rpIdHash = str_repeat("\x00", 32);
    $bytes = $rpIdHash.chr(0x45).pack('N', 1).str_repeat("\x00", 4); // AT set but no credential data

    AuthenticatorData::parse($bytes);
})->throws(MalformedCborException::class);

it('rejects a zero-length credential id', function (): void {
    // AT set, 16-byte AAGUID present, but the credential-id length is zero.
    $bytes = str_repeat("\x00", 32).chr(0x41).pack('N', 1).str_repeat("\x00", 16)."\x00\x00";

    AuthenticatorData::parse($bytes);
})->throws(MalformedCborException::class);

it('rejects a COSE key region that is not a map', function (): void {
    // AT set, a 1-byte credential id, then a CBOR integer where the COSE map
    // should be.
    $bytes = str_repeat("\x00", 32).chr(0x41).pack('N', 1).str_repeat("\x00", 16)."\x00\x01"."\xaa"."\x00";

    AuthenticatorData::parse($bytes);
})->throws(MalformedCborException::class);

it('parses authenticator data with a trailing extension map', function (): void {
    // rpIdHash + flags(UP|ED) + signCount + one CBOR extension map (empty).
    $bytes = str_repeat("\x00", 32).chr(0x81).pack('N', 5)."\xa0";
    $parsed = AuthenticatorData::parse($bytes);

    expect($parsed->flags->extensionData)->toBeTrue()
        ->and($parsed->signCount)->toBe(5);
});

it('rejects extension flag set with no extension present', function (): void {
    AuthenticatorData::parse(str_repeat("\x00", 32).chr(0x81).pack('N', 5));
})->throws(MalformedCborException::class);

it('rejects malformed extension data', function (): void {
    // ED set but the trailing bytes are not a single clean CBOR item.
    AuthenticatorData::parse(str_repeat("\x00", 32).chr(0x81).pack('N', 5)."\xa0\xff");
})->throws(MalformedCborException::class);

it('decodes the flag bits', function (): void {
    $flags = AuthenticatorFlags::fromByte(0xDD);

    expect($flags->userPresent)->toBeTrue()
        ->and($flags->userVerified)->toBeTrue()
        ->and($flags->backupEligible)->toBeTrue()
        ->and($flags->backupState)->toBeTrue()
        ->and($flags->attestedCredentialData)->toBeTrue()
        ->and($flags->extensionData)->toBeTrue();
});

it('decodes a byte with no flags set', function (): void {
    $flags = AuthenticatorFlags::fromByte(0x00);

    expect($flags->userPresent)->toBeFalse()
        ->and($flags->extensionData)->toBeFalse();
});
