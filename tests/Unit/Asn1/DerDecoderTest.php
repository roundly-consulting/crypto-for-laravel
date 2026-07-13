<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Asn1\DerDecoder;
use RoundlyConsulting\Crypto\Asn1\DerElement;
use RoundlyConsulting\Crypto\Asn1\MalformedDerException;
use RoundlyConsulting\Crypto\Asn1\TagClass;

/*
 * The decoder is a PARSER. Every test here asks only "what do the bytes say" —
 * and the negative half asserts that a BER-lax, padded, oversized, or truncated
 * encoding is a typed rejection rather than a lenient reinterpretation.
 */

function derLength(int $length): string
{
    if ($length < 0x80) {
        return chr($length);
    }

    $bytes = '';

    while ($length > 0) {
        $bytes = chr($length & 0xFF).$bytes;
        $length >>= 8;
    }

    return chr(0x80 | strlen($bytes)).$bytes;
}

function derTlv(int $identifier, string $contents): string
{
    return chr($identifier).derLength(strlen($contents)).$contents;
}

function derSequence(string ...$parts): string
{
    return derTlv(0x30, implode('', $parts));
}

function decodeDer(string $der): DerElement
{
    return (new DerDecoder)->decode($der);
}

// ── Positive: X.690 shapes the X.509/attestation world actually uses ────────

it('decodes a sequence of primitives', function (): void {
    $der = derSequence(
        derTlv(0x02, "\x2A"),                                       // INTEGER 42
        derTlv(0x06, (string) hex2bin('2A864886F763640802')),        // OID 1.2.840.113635.100.8.2
        derTlv(0x04, 'nonce'),                                      // OCTET STRING
        derTlv(0x01, "\xFF"),                                       // BOOLEAN TRUE
        derTlv(0x05, ''),                                           // NULL
    );

    $element = decodeDer($der);

    expect($element->class)->toBe(TagClass::Universal)
        ->and($element->tag)->toBe(16)
        ->and($element->constructed)->toBeTrue()
        ->and($element->children())->toHaveCount(5)
        ->and($element->children()[0]->integer())->toBe(42)
        ->and($element->children()[1]->oid())->toBe('1.2.840.113635.100.8.2')
        ->and($element->children()[2]->octetString())->toBe('nonce')
        ->and($element->children()[3]->boolean())->toBeTrue()
        ->and($element->children()[4]->isNull())->toBeTrue()
        ->and($element->children()[0]->isNull())->toBeFalse();
});

it('decodes the OIDs the X.509 world is made of', function (string $hex, string $expected): void {
    expect(decodeDer(derTlv(0x06, (string) hex2bin($hex)))->oid())->toBe($expected);
})->with([
    ['551D13', '2.5.29.19'],                    // basicConstraints
    ['551D11', '2.5.29.17'],                    // subjectAltName
    ['2A864886F763640802', '1.2.840.113635.100.8.2'],     // the Apple nonce extension
    ['2B0601040182E51C010104', '1.3.6.1.4.1.45724.1.1.4'], // id-fido-gen-ce-aaguid
    ['6781050803', '2.23.133.8.3'],              // tcg-kp-AIKCertificate
    ['2A03', '1.2.3'],
    ['00', '0.0'],
    ['4F', '1.39'],                              // the 79 boundary of the packed first octet
    ['50', '2.0'],                               // and the 80 boundary
]);

it('decodes nested constructed elements', function (): void {
    $inner = derSequence(derTlv(0x04, 'deep'));
    $element = decodeDer(derSequence(derSequence($inner)));

    expect($element->children()[0]->children()[0]->children()[0]->octetString())->toBe('deep');
});

it('finds an explicit context-specific field by tag', function (): void {
    // The Apple nonce shape: SEQUENCE { [1] { OCTET STRING nonce } }
    $der = derSequence(derTlv(0xA1, derTlv(0x04, 'the-nonce')));

    $element = decodeDer($der);
    $tagged = $element->tagged(1);

    expect($tagged)->not->toBeNull()
        ->and($tagged?->class)->toBe(TagClass::ContextSpecific)
        ->and($tagged?->constructed)->toBeTrue()
        ->and($tagged?->children()[0]->octetString())->toBe('the-nonce')
        ->and($element->tagged(2))->toBeNull();
});

it('decodes the high-tag-number form Android key descriptions use', function (): void {
    // [702] EXPLICIT — a tag number that does not fit the five low bits.
    $der = derSequence("\xBF\x85\x3E".derLength(3).derTlv(0x02, "\x00"));

    $child = decodeDer($der)->children()[0];

    expect($child->class)->toBe(TagClass::ContextSpecific)
        ->and($child->tag)->toBe(702)
        ->and($child->children()[0]->integer())->toBe(0);
});

it('decodes the long length form once the content needs it', function (): void {
    $contents = str_repeat("\x41", 300);

    $element = decodeDer(derTlv(0x04, $contents));

    expect($element->octetString())->toBe($contents)
        ->and(strlen($element->contents))->toBe(300);
});

it('decodes integers across the sign and width boundaries', function (string $contents, int|string $expected): void {
    expect(decodeDer(derTlv(0x02, $contents))->integer())->toBe($expected);
})->with([
    ["\x00", 0],
    ["\x7F", 127],
    ["\x00\x80", 128],
    ["\xFF", -1],
    ["\x80", -128],
    ["\xFF\x7F", -129],
    ["\x7F\xFF\xFF\xFF\xFF\xFF\xFF\xFF", PHP_INT_MAX],
    ["\x80\x00\x00\x00\x00\x00\x00\x00", PHP_INT_MIN],
    // Wider than 64 bits — an RSA modulus is an INTEGER too, so it comes back as
    // its raw two's-complement bytes rather than a lossy float.
    ["\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", "\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"],
]);

it('decodes an empty octet string and an empty sequence', function (): void {
    expect(decodeDer(derTlv(0x04, ''))->octetString())->toBe('')
        ->and(decodeDer(derSequence())->children())->toBe([]);
});

it('reports how many bytes the leading element consumed', function (): void {
    $first = derTlv(0x04, 'one');
    $result = (new DerDecoder)->decodeFirst($first.derTlv(0x04, 'two'));

    expect($result->bytesRead)->toBe(strlen($first))
        ->and($result->element->octetString())->toBe('one');
});

// ── Negative: DER is canonical, and hostile input is bounded ────────────────

it('rejects an indefinite length', function (): void {
    expect(fn (): mixed => decodeDer("\x30\x80\x04\x01\x41\x00\x00"))
        ->toThrow(MalformedDerException::class, 'indefinite-length');
});

it('rejects a non-minimal length', function (): void {
    // Length 5 written in the long form, which the short form already covers.
    expect(fn (): mixed => decodeDer("\x04\x81\x05".'hello'))
        ->toThrow(MalformedDerException::class, 'minimal form')
        // A long form padded with a leading zero octet.
        ->and(fn (): mixed => decodeDer("\x04\x82\x00\x05".'hello'))
        ->toThrow(MalformedDerException::class, 'minimal form');
});

it('rejects the reserved length form', function (): void {
    expect(fn (): mixed => decodeDer("\x04\xFF\x01"))
        ->toThrow(MalformedDerException::class, 'reserved');
});

it('rejects a length wider than eight octets', function (): void {
    expect(fn (): mixed => decodeDer("\x04\x89".str_repeat("\xFF", 9)))
        ->toThrow(MalformedDerException::class, 'eight octets');
});

it('never over-reads a length longer than the buffer', function (): void {
    // Declares 200 bytes of content and supplies four.
    expect(fn (): mixed => decodeDer("\x04\x81\xC8".'abcd'))
        ->toThrow(MalformedDerException::class, 'ended inside an element');
});

it('rejects an eight-octet length that overflows a PHP int', function (): void {
    expect(fn (): mixed => decodeDer("\x04\x88".str_repeat("\xFF", 8)))
        ->toThrow(MalformedDerException::class, 'over the 65536-byte cap');
});

it('rejects input truncated at every byte boundary', function (): void {
    $der = derSequence(derTlv(0x04, 'hello'), derTlv(0x02, "\x01"));

    for ($length = 1; $length < strlen($der); $length++) {
        expect(fn (): mixed => decodeDer(substr($der, 0, $length)))
            ->toThrow(MalformedDerException::class);
    }

    expect(fn (): mixed => decodeDer(''))->toThrow(MalformedDerException::class);
});

it('rejects trailing bytes after the top-level element', function (): void {
    expect(fn (): mixed => decodeDer(derTlv(0x04, 'hi')."\x00\x00"))
        ->toThrow(MalformedDerException::class, '2 trailing bytes');
});

it('rejects a nesting bomb rather than the stack', function (): void {
    $der = derTlv(0x04, '');

    for ($i = 0; $i < 20; $i++) {
        $der = derSequence($der);
    }

    expect(fn (): mixed => decodeDer($der))
        ->toThrow(MalformedDerException::class, 'deeper than 16 levels');
});

it('rejects an element bomb rather than unbounded work', function (): void {
    $der = derSequence(str_repeat("\x05\x00", DerDecoder::MAX_ELEMENTS + 1));

    expect(fn (): mixed => decodeDer($der))
        ->toThrow(MalformedDerException::class, 'more than 4096 elements');
});

it('rejects input over the size cap before parsing a byte', function (): void {
    expect(fn (): mixed => decodeDer(str_repeat("\x41", DerDecoder::MAX_INPUT_BYTES + 1)))
        ->toThrow(MalformedDerException::class, 'over the 65536-byte cap');
});

it('rejects a constructed-primitive form mismatch', function (): void {
    // A constructed INTEGER (0x22) and a primitive SEQUENCE (0x10) are both BER
    // shapes DER forbids — the classic parser differential.
    expect(fn (): mixed => decodeDer("\x22\x03".derTlv(0x02, "\x01")))
        ->toThrow(MalformedDerException::class, 'must be primitive')
        ->and(fn (): mixed => decodeDer("\x10\x00"))
        ->toThrow(MalformedDerException::class, 'must be constructed');
});

it('rejects a non-minimal high-tag-number encoding', function (): void {
    expect(fn (): mixed => decodeDer("\xBF\x80\x01\x00"))
        ->toThrow(MalformedDerException::class, 'minimal form')
        // Tag 1 written in the long form, which the low bits already cover.
        ->and(fn (): mixed => decodeDer("\xBF\x01\x00"))
        ->toThrow(MalformedDerException::class, 'minimal form')
        ->and(fn (): mixed => decodeDer("\xBF\xFF\xFF\xFF\xFF\x7F\x00"))
        ->toThrow(MalformedDerException::class, 'four octets');
});

it('rejects a padded integer', function (): void {
    expect(fn (): mixed => decodeDer(derTlv(0x02, "\x00\x01"))->integer())
        ->toThrow(MalformedDerException::class, 'padded')
        ->and(fn (): mixed => decodeDer(derTlv(0x02, "\xFF\x80"))->integer())
        ->toThrow(MalformedDerException::class, 'padded')
        ->and(fn (): mixed => decodeDer(derTlv(0x02, ''))->integer())
        ->toThrow(MalformedDerException::class, 'empty');
});

it('rejects a malformed object identifier', function (): void {
    expect(fn (): mixed => decodeDer(derTlv(0x06, ''))->oid())
        ->toThrow(MalformedDerException::class, 'empty')
        // A subidentifier padded with a leading 0x80.
        ->and(fn (): mixed => decodeDer(derTlv(0x06, "\x2A\x80\x01"))->oid())
        ->toThrow(MalformedDerException::class, 'padded')
        // The final subidentifier never terminates.
        ->and(fn (): mixed => decodeDer(derTlv(0x06, "\x2A\x86"))->oid())
        ->toThrow(MalformedDerException::class, 'unterminated')
        ->and(fn (): mixed => decodeDer(derTlv(0x06, "\x2A".str_repeat("\xFF", 10)."\x01"))->oid())
        ->toThrow(MalformedDerException::class, 'overflows');
});

it('rejects a BER-lax boolean', function (): void {
    expect(fn (): mixed => decodeDer(derTlv(0x01, "\x01"))->boolean())
        ->toThrow(MalformedDerException::class, '0xFF')
        ->and(fn (): mixed => decodeDer(derTlv(0x01, "\xFF\xFF"))->boolean())
        ->toThrow(MalformedDerException::class, 'single octet')
        ->and(decodeDer(derTlv(0x01, "\x00"))->boolean())->toBeFalse();
});

it('rejects a NULL carrying content', function (): void {
    expect(fn (): mixed => decodeDer(derTlv(0x05, "\x00")))
        ->toThrow(MalformedDerException::class, 'content octets');
});

// ── The typed readers refuse a tag they do not admit ────────────────────────

it('refuses to read a tag it does not admit', function (): void {
    $octet = decodeDer(derTlv(0x04, 'bytes'));
    $sequence = decodeDer(derSequence());

    expect(fn (): mixed => $octet->oid())->toThrow(MalformedDerException::class, 'expected OBJECT IDENTIFIER')
        ->and(fn (): mixed => $octet->integer())->toThrow(MalformedDerException::class, 'expected INTEGER')
        ->and(fn (): mixed => $octet->boolean())->toThrow(MalformedDerException::class, 'expected BOOLEAN')
        ->and(fn (): mixed => $sequence->octetString())->toThrow(MalformedDerException::class, 'expected OCTET STRING')
        ->and(fn (): mixed => $octet->children())->toThrow(MalformedDerException::class, 'no children')
        ->and(fn (): mixed => $octet->tagged(0))->toThrow(MalformedDerException::class, 'no children');
});
