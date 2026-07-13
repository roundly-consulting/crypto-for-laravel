<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Asn1\DerDecoder;
use RoundlyConsulting\Crypto\Asn1\MalformedDerException;
use RoundlyConsulting\Crypto\Exceptions\CryptoException;

/*
 * An exception whose message does not say what is wrong is a support ticket. Pin
 * the diagnosis in each one.
 */

it('describes every DER failure', function (): void {
    expect(MalformedDerException::truncated())->toBeInstanceOf(CryptoException::class)
        ->and(MalformedDerException::truncated()->getMessage())->toContain('ended inside an element')
        ->and(MalformedDerException::indefiniteLength()->getMessage())->toContain('BER, not DER')
        ->and(MalformedDerException::nonMinimalLength()->getMessage())->toContain('minimal form')
        ->and(MalformedDerException::reservedLength()->getMessage())->toContain('reserved')
        ->and(MalformedDerException::nonMinimalTag()->getMessage())->toContain('tag number')
        ->and(MalformedDerException::trailingBytes(3)->getMessage())->toContain('3 trailing bytes')
        ->and(MalformedDerException::tooDeep(DerDecoder::MAX_DEPTH)->getMessage())->toContain('16')
        ->and(MalformedDerException::tooLarge(70_000, DerDecoder::MAX_INPUT_BYTES)->getMessage())
        ->toContain('70000')->toContain('65536')
        ->and(MalformedDerException::tooManyElements(DerDecoder::MAX_ELEMENTS)->getMessage())->toContain('4096')
        ->and(MalformedDerException::unexpectedTag('OCTET STRING', 6)->getMessage())
        ->toContain('OCTET STRING')->toContain('tag 6')
        ->and(MalformedDerException::notConstructed(4)->getMessage())->toContain('no children')
        ->and(MalformedDerException::mustBePrimitive(2)->getMessage())->toContain('must be primitive')
        ->and(MalformedDerException::mustBeConstructed(16)->getMessage())->toContain('must be constructed')
        ->and(MalformedDerException::malformedContents('INTEGER', 'it is padded')->getMessage())
        ->toContain('INTEGER')->toContain('padded');
});
