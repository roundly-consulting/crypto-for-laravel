<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Asn1\DerDecoder;
use RoundlyConsulting\Crypto\Testing\TestCertificates;
use RoundlyConsulting\Crypto\Testing\TestLeafOptions;
use RoundlyConsulting\Crypto\X509\Certificate;
use RoundlyConsulting\Crypto\X509\Extension;
use RoundlyConsulting\Crypto\X509\MalformedCertificateException;

/*
 * The certificate's structural FACTS: which extensions it carries, whether they
 * were marked critical, what version it is, and whether its subject is empty. The
 * bytes come back raw — this package never says what they mean.
 */

it('hands back an extension as raw DER, interpreting nothing', function (): void {
    // The Apple WebAuthn shape: SEQUENCE { [1] { OCTET STRING nonce } }.
    $nonce = random_bytes(32);
    $der = "\x30\x24\xA1\x22\x04\x20".$nonce;

    $leaf = TestCertificates::chain(
        length: 2,
        leafOptions: new TestLeafOptions(rawExtensions: ['1.2.840.113635.100.8.2' => $der]),
    )->leaf();

    $extension = $leaf->extension('1.2.840.113635.100.8.2');

    expect($extension)->toBeInstanceOf(Extension::class)
        ->and($extension?->oid)->toBe('1.2.840.113635.100.8.2')
        ->and($extension?->critical)->toBeFalse()
        // Byte-for-byte what was minted: no pretty-printing, no interpretation.
        ->and($extension?->der)->toBe($der)
        // And it is the caller — not crypto — who decodes what it means.
        ->and((new DerDecoder)->decode((string) $extension?->der)->tagged(1)?->children()[0]->octetString())
        ->toBe($nonce);
});

it('reports a missing extension as null', function (): void {
    expect(TestCertificates::chain(length: 1)->leaf()->extension('1.2.840.113635.100.8.2'))->toBeNull();
});

it('reads an extension criticality flag', function (): void {
    $leaf = TestCertificates::chain(
        length: 2,
        leafOptions: new TestLeafOptions(
            rawExtensions: ['1.3.6.1.4.1.45724.1.1.4' => "\x04\x10".str_repeat("\x07", 16)],
            criticalRawExtensions: true,
        ),
    )->leaf();

    expect($leaf->extension('1.3.6.1.4.1.45724.1.1.4')?->critical)->toBeTrue()
        // basicConstraints and keyUsage are minted critical; the SKI never is.
        ->and($leaf->extension('2.5.29.19')?->critical)->toBeTrue()
        ->and($leaf->extension('2.5.29.14')?->critical)->toBeFalse();
});

it('surfaces basicConstraints as the bytes CA:FALSE actually encodes to', function (): void {
    $chain = TestCertificates::chain(length: 2);

    // Leaf: SEQUENCE {} (cA defaults to FALSE). Root: SEQUENCE { BOOLEAN TRUE }.
    $leaf = (new DerDecoder)->decode((string) $chain->leaf()->extension('2.5.29.19')?->der);
    $root = (new DerDecoder)->decode((string) $chain->root()->extension('2.5.29.19')?->der);

    expect($leaf->children())->toBe([])
        ->and($root->children()[0]->boolean())->toBeTrue();
});

it('round-trips a real subjectAltName through the DER walk', function (): void {
    $leaf = TestCertificates::chain(length: 2, dnsNames: ['a.example', 'b.example'])->leaf();

    $san = (new DerDecoder)->decode((string) $leaf->extension('2.5.29.17')?->der);

    // GeneralNames ::= SEQUENCE OF GeneralName; dNSName is [2] IMPLICIT IA5String.
    $names = array_map(
        static fn ($general): string => $general->contents,
        $san->children(),
    );

    expect($names)->toBe(['a.example', 'b.example'])
        ->and($leaf->dnsNames())->toBe($names);
});

it('lists every extension keyed by OID', function (): void {
    $leaf = TestCertificates::chain(length: 1, dnsNames: ['x.example'])->leaf();

    expect(array_keys($leaf->extensions()))
        ->toContain('2.5.29.19', '2.5.29.15', '2.5.29.37', '2.5.29.14', '2.5.29.17')
        ->and($leaf->extensions()['2.5.29.19'])->toBe($leaf->extension('2.5.29.19'));
});

it('mints and reads an extended key usage', function (): void {
    $leaf = TestCertificates::chain(
        length: 2,
        leafOptions: new TestLeafOptions(extendedKeyUsageOids: ['2.23.133.8.3']),
    )->leaf();

    $eku = (new DerDecoder)->decode((string) $leaf->extension('2.5.29.37')?->der);

    expect(array_map(static fn ($purpose): string => $purpose->oid(), $eku->children()))
        ->toBe(['2.23.133.8.3']);
});

it('mints a critical dirName SAN carrying the TCG attributes', function (): void {
    $leaf = TestCertificates::chain(
        length: 2,
        leafOptions: new TestLeafOptions(directoryNameSan: [
            '2.23.133.2.1' => 'id:524F554E',
            '2.23.133.2.2' => 'TestTPM',
            '2.23.133.2.3' => 'id:00010002',
        ]),
    )->leaf();

    $san = $leaf->extension('2.5.29.17');
    $directoryName = (new DerDecoder)->decode((string) $san?->der)->tagged(4);

    // RFC 5280 requires SAN to be critical when the subject is empty; the fixture
    // marks it critical whenever it carries a dirName, which is the TPM shape.
    expect($san?->critical)->toBeTrue()
        ->and($directoryName)->not->toBeNull();

    $attributes = [];

    foreach ($directoryName?->children()[0]->children() ?? [] as $rdn) {
        $pair = $rdn->children()[0];
        $attributes[$pair->children()[0]->oid()] = $pair->children()[1]->contents;
    }

    expect($attributes)->toBe([
        '2.23.133.2.1' => 'id:524F554E',
        '2.23.133.2.2' => 'TestTPM',
        '2.23.133.2.3' => 'id:00010002',
    ]);
});

it('reports the certificate version', function (): void {
    expect(TestCertificates::chain(length: 1)->leaf()->version())->toBe(3);
});

it('reads a version-1 certificate as v1', function (): void {
    // A v1 certificate has no extensions and no version field at all — the
    // TBSCertificate simply starts at the serial number.
    $v1 = Certificate::fromPem(readFixture('x509/v1.pem'));

    expect($v1->version())->toBe(1)
        ->and($v1->extensions())->toBe([])
        ->and($v1->extension('2.5.29.19'))->toBeNull()
        ->and($v1->subjectIsEmpty())->toBeFalse();
});

it('tells an empty subject from a populated one', function (): void {
    $empty = TestCertificates::chain(
        length: 2,
        leafOptions: new TestLeafOptions(
            directoryNameSan: ['2.23.133.2.1' => 'id:524F554E'],
            emptySubject: true,
        ),
    )->leaf();

    expect($empty->subjectIsEmpty())->toBeTrue()
        ->and($empty->commonName())->toBeNull()
        ->and(TestCertificates::chain(length: 1)->leaf()->subjectIsEmpty())->toBeFalse();
});

it('mints the packed subject organizational unit', function (): void {
    $leaf = TestCertificates::chain(
        length: 2,
        leafOptions: new TestLeafOptions(subjectOrganizationalUnit: 'Authenticator Attestation'),
    )->leaf();

    expect($leaf->subject()->organizationalUnit)->toBe('Authenticator Attestation')
        ->and($leaf->subjectIsEmpty())->toBeFalse();
});

it('parses the extension list eagerly, so no getter can throw later', function (): void {
    // The structural walk happens at construction: a certificate that constructed
    // has already been walked, exactly as the class's other accessors promise.
    $leaf = TestCertificates::chain(length: 1)->leaf();
    $reparsed = Certificate::fromDer($leaf->der());

    expect($reparsed->extensions())->toEqual($leaf->extensions())
        ->and($reparsed->version())->toBe($leaf->version());
});

it('refuses a certificate claiming an X.509 version that does not exist', function (): void {
    // OpenSSL reads the version field without ruling on it, so a certificate can
    // arrive claiming v4. The DER walk is where that stops being read at all.
    $der = TestCertificates::chain(length: 1)->leaf()->der();
    $patched = str_replace("\xA0\x03\x02\x01\x02", "\xA0\x03\x02\x01\x03", $der, $count);

    expect($count)->toBe(1)
        ->and(fn (): mixed => Certificate::fromDer($patched))
        ->toThrow(MalformedCertificateException::class, 'could not be parsed');
});

it('refuses a certificate whose structure openssl accepts but DER does not', function (): void {
    // A garbage body is caught by OpenSSL first; the DER walk is the second net,
    // and either way the failure is the one typed exception.
    expect(fn (): mixed => Certificate::fromDer(random_bytes(64)))
        ->toThrow(MalformedCertificateException::class);
});
