<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Signature\Ec\Der;
use RoundlyConsulting\Crypto\Signature\InvalidSignatureException;

it('round-trips a raw signature through DER', function (): void {
    $raw = random_bytes(64);

    // ltrim/pad means only signatures without leading zero bytes round-trip
    // byte-for-byte; force non-zero high bytes to keep the fixture exact.
    $raw[0] = "\x7f";
    $raw[32] = "\x7f";

    expect(Der::toRaw(Der::fromRaw($raw)))->toBe($raw);
});

it('pads integers whose high bit is set so they stay positive', function (): void {
    $vectors = cryptoVectors()['ecdsa_der'];
    $der = Der::fromRaw(hex2bin($vectors['high_bit_raw']));

    // 0x30 SEQ, then 0x02 INT, length 0x21 (33), then 0x00 pad, then 0x80…
    expect(bin2hex(substr($der, 2, 4)))->toBe('02210080');
});

it('strips superfluous leading zero bytes', function (): void {
    $vectors = cryptoVectors()['ecdsa_der'];
    $der = Der::fromRaw(hex2bin($vectors['leading_zero_raw']));

    // First integer encodes as a single 0x05 byte: 0x02 (INT) 0x01 (len) 0x05.
    expect(bin2hex(substr($der, 2, 3)))->toBe('020105');
});

it('encodes a maximal signature as a valid short-form sequence', function (): void {
    $vectors = cryptoVectors()['ecdsa_der'];
    $der = Der::fromRaw(hex2bin($vectors['maximal_raw']));

    expect(bin2hex($der[0]))->toBe('30')
        ->and(bin2hex($der[1]))->toBe('46')
        ->and(strlen($der))->toBe(72);
});

it('accepts a real openssl ECDSA signature as valid DER', function (): void {
    $der = hex2bin(cryptoVectors()['es256']['sig_der']);

    expect(Der::isValid($der))->toBeTrue();
});

it('converts a real openssl DER signature to the JOSE raw form', function (): void {
    $es256 = cryptoVectors()['es256'];

    expect(bin2hex(Der::toRaw(hex2bin($es256['sig_der']))))->toBe($es256['sig_raw'])
        ->and(strlen(Der::toRaw(hex2bin($es256['sig_der']))))->toBe(64);
});

it('round-trips 48-byte (P-384) coordinates', function (): void {
    $raw = random_bytes(96);
    $raw[0] = "\x7f";
    $raw[48] = "\x7f";

    expect(Der::toRaw(Der::fromRaw($raw, 48), 48))->toBe($raw);
});

it('round-trips 66-byte (P-521) coordinates including leading-zero padding', function (): void {
    // P-521 r/s routinely carry leading zero bytes; the codec must re-pad to 66.
    $raw = str_repeat("\x00", 2)."\x7f".random_bytes(63).str_repeat("\x00", 3)."\x01".random_bytes(62);

    expect(strlen($raw))->toBe(132)
        ->and(Der::toRaw(Der::fromRaw($raw, 66), 66))->toBe($raw);
});

it('round-trips the committed P-521 signature (high-bit and leading-zero limbs)', function (): void {
    $raw = hex2bin(cryptoVectors()['es512']['sig_raw']);

    expect(Der::isValid(Der::fromRaw($raw, 66)))->toBeTrue()
        ->and(Der::toRaw(Der::fromRaw($raw, 66), 66))->toBe($raw);
});

it('rejects a raw signature of the wrong length', function (): void {
    Der::fromRaw('too short');
})->throws(InvalidSignatureException::class);

it('rejects DER that is not a sequence', function (): void {
    Der::toRaw("\x31\x06\x02\x01\x01\x02\x01\x01");
})->throws(InvalidSignatureException::class);

it('round-trips oversized coordinates using long-form DER lengths', function (): void {
    // 64-byte coordinates (high bit clear) force a long-form SEQUENCE length and
    // exercise the multi-byte length encoder/parser.
    $raw = str_repeat("\x7f", 128);
    $der = Der::fromRaw($raw, 64);

    expect(Der::isValid($der))->toBeTrue()
        ->and(Der::toRaw($der, 64))->toBe($raw);
});

it('encodes an all-zero coordinate as a single zero byte', function (): void {
    $der = Der::fromRaw(str_repeat("\x00", 64));

    // 0x02 (INT) 0x01 (len) 0x00 for each of r and s.
    expect(bin2hex(substr($der, 2, 3)))->toBe('020100');
});

it('rejects DER whose integers exceed the coordinate size', function (): void {
    $der = Der::fromRaw(str_repeat("\x7f", 128), 64);

    // The same DER decoded as P-256 (32-byte coords) is out of range.
    Der::toRaw($der, 32);
})->throws(InvalidSignatureException::class);

it('reports malformed DER as invalid', function (string $der): void {
    expect(Der::isValid($der))->toBeFalse();
})->with([
    'too short' => ["\x30\x02\x02\x01"],
    'not a sequence' => ["\x31\x06\x02\x01\x01\x02\x01\x01"],
    'non-minimal integer' => ["\x30\x08\x02\x02\x00\x01\x02\x02\x00\x01"],
    'trailing bytes' => ["\x30\x06\x02\x01\x01\x02\x01\x01\xff"],
    'negative integer' => ["\x30\x06\x02\x01\x80\x02\x01\x01"],
    'first element is not an integer' => ["\x30\x06\x03\x01\x01\x02\x01\x01"],
    'zero-length integer' => ["\x30\x06\x02\x00\x02\x02\x01\x01"],
    'oversized long-form length' => ["\x30\x85\x01\x01\x01\x01\x01\x01"],
    'indefinite long-form length' => ["\x30\x80\x02\x01\x01\x02\x01\x01"],
]);
