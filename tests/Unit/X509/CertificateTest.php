<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use RoundlyConsulting\Crypto\Codec\Base64;
use RoundlyConsulting\Crypto\Codec\InvalidEncodingException;
use RoundlyConsulting\Crypto\Hash\HashAlgorithm;
use RoundlyConsulting\Crypto\Signature\Key\EcKey;
use RoundlyConsulting\Crypto\Signature\Key\RsaKey;
use RoundlyConsulting\Crypto\Signature\WeakKeyException;
use RoundlyConsulting\Crypto\Testing\TestCertificates;
use RoundlyConsulting\Crypto\Testing\TestLeafOptions;
use RoundlyConsulting\Crypto\X509\Certificate;
use RoundlyConsulting\Crypto\X509\Chain;
use RoundlyConsulting\Crypto\X509\DistinguishedName;
use RoundlyConsulting\Crypto\X509\InvalidLeewayException;
use RoundlyConsulting\Crypto\X509\MalformedCertificateException;

// ── encodings ───────────────────────────────────────────────────────────────

it('reads the same certificate from PEM, DER and x5c base64', function (): void {
    $certificate = TestCertificates::chain()->leaf();

    $fromPem = Certificate::fromPem($certificate->pem());
    $fromDer = Certificate::fromDer($certificate->der());
    $fromBase64 = Certificate::fromBase64($certificate->base64());

    expect($fromPem->der())->toBe($certificate->der())
        ->and($fromDer->der())->toBe($certificate->der())
        ->and($fromBase64->der())->toBe($certificate->der())
        ->and($fromDer->pem())->toBe($certificate->pem())
        ->and($fromBase64->base64())->toBe($certificate->base64())
        ->and($certificate->equals($fromDer))->toBeTrue();
});

it('encodes x5c as standard base64, not base64url', function (): void {
    $certificate = TestCertificates::chain()->leaf();

    expect($certificate->base64())->toBe(Base64::encode($certificate->der()))
        ->and(Base64::decode($certificate->base64()))->toBe($certificate->der());
});

it('reports two different certificates as unequal', function (): void {
    $chain = TestCertificates::chain();

    expect($chain->leaf()->equals($chain->root()))->toBeFalse();
});

// ── fingerprints ────────────────────────────────────────────────────────────

it('fingerprints exactly as openssl does, in lower-case hex', function (string $algorithm): void {
    $certificate = TestCertificates::chain()->leaf();
    $hash = HashAlgorithm::from($algorithm);

    $fingerprint = $certificate->fingerprint($hash);

    expect($fingerprint)->toBe(openssl_x509_fingerprint($certificate->pem(), $algorithm))
        ->and($fingerprint)->toBe(strtolower($fingerprint))
        ->and($fingerprint)->not->toContain(':');
})->with(['sha1', 'sha256', 'sha384', 'sha512']);

// ── facts ───────────────────────────────────────────────────────────────────

it('exposes the subject, issuer and serial', function (): void {
    $chain = TestCertificates::chain(commonName: 'leaf.example');
    $leaf = $chain->leaf();

    expect($leaf->subject())->toBeInstanceOf(DistinguishedName::class)
        ->and($leaf->commonName())->toBe('leaf.example')
        ->and($leaf->subject()->organization)->toBe('Crypto Test')
        ->and($leaf->subject()->country)->toBe('SK')
        ->and($leaf->subject()->locality)->toBeNull()
        ->and($leaf->issuer()->commonName)->toBe('Crypto Test Intermediate CA 1')
        ->and($leaf->serialNumber())->toBe(strtoupper((string) $leaf->serialNumber()))
        ->and($leaf->signatureAlgorithm())->toBe('ecdsa-with-SHA256')
        ->and($leaf->subject()->toString())->toBe('CN=leaf.example, O=Crypto Test, C=SK');
});

it('reads the DNS names of subjectAltName and ignores everything else', function (): void {
    $withSans = TestCertificates::selfSigned(dnsNames: ['app.example', '*.wildcard.example']);
    $without = TestCertificates::chain();

    expect($withSans->leaf()->dnsNames())->toBe(['app.example', '*.wildcard.example'])
        ->and($without->leaf()->dnsNames())->toBe([]);
});

it('reads each dNSName from the DER, so a comma inside one cannot forge a second', function (): void {
    // One dNSName whose text looks like two: OpenSSL pretty-prints it as
    // "DNS:evil.example, DNS:victim.example", which a text split reads as two names.
    $leaf = TestCertificates::selfSigned(dnsNames: ['evil.example, DNS:victim.example'])->leaf();

    expect($leaf->dnsNames())->toBe(['evil.example, DNS:victim.example'])
        ->and($leaf->dnsNames())->not->toContain('victim.example');
});

it('reads only the dNSName entries of a mixed subjectAltName, verbatim', function (): void {
    $general = static fn (int $tag, string $value): string => chr(0x80 | $tag).chr(strlen($value)).$value;
    $names = $general(2, 'a.example')
        .$general(1, 'root@a.example')                 // rfc822Name
        .$general(7, "\x7F\x00\x00\x01")               // iPAddress
        .$general(6, 'https://a.example/')             // uniformResourceIdentifier
        .$general(2, "bank.example\x00.evil.example"); // a NUL stays IN the name

    $leaf = TestCertificates::selfSigned(
        dnsNames: [],
        options: new TestLeafOptions(rawExtensions: ['2.5.29.17' => "\x30".chr(strlen($names)).$names]),
    )->leaf();

    expect($leaf->dnsNames())->toBe(['a.example', "bank.example\x00.evil.example"]);
});

it('refuses a certificate whose subjectAltName is not a valid GeneralNames', function (string $san): void {
    expect(fn (): mixed => TestCertificates::selfSigned(
        dnsNames: [],
        options: new TestLeafOptions(rawExtensions: ['2.5.29.17' => $san]),
    ))->toThrow(MalformedCertificateException::class, 'could not be parsed');
})->with([
    'a SET, not a SEQUENCE' => ["\x31\x0B\x82\x09a.example"],
    'a constructed dNSName' => ["\x30\x0D\xA2\x0B\x16\x09a.example"],
    'a dNSName outside IA5' => ["\x30\x0C\x82\x0A\xC3\xA4.example"],
]);

it('hands over an EC or RSA public key that verifies real signatures', function (string $keyType, string $class): void {
    $chain = TestCertificates::chain(leafKeyType: $keyType);

    $key = $chain->leaf()->publicKey();
    $signature = $chain->leafKey->verifier()->sign('payload');

    expect($key)->toBeInstanceOf($class)
        ->and($key->verifier()->verify('payload', $signature))->toBeTrue();
})->with([
    ['EC', EcKey::class],
    ['RSA', RsaKey::class],
]);

it('applies the package key policy to a certificate key', function (): void {
    // A 1024-bit certificate key parses fine but is refused as a key.
    $certificate = Certificate::fromPem(readFixture('x509/weak-1024.pem'));

    expect($certificate->commonName())->toBe('weak.crypto-test.example')
        ->and(fn (): mixed => $certificate->publicKey())->toThrow(WeakKeyException::class);
});

it('refuses a certificate whose key type it cannot express', function (): void {
    $certificate = Certificate::fromPem(readFixture('x509/ed25519.pem'));

    expect(fn (): mixed => $certificate->publicKey())
        ->toThrow(MalformedCertificateException::class, 'does not support');
});

it('refuses a certificate whose key algorithm OpenSSL cannot load', function (): void {
    // A structurally valid certificate whose SPKI names an unassigned algorithm
    // OID: readable, parseable, but there is no key to be had — and no warning.
    $certificate = Certificate::fromPem(readFixture('x509/unknown-key-algorithm.pem'));

    expect($certificate->commonName())->toBe('weak.crypto-test.example')
        ->and(fn (): mixed => $certificate->publicKey())
        ->toThrow(MalformedCertificateException::class, 'does not support');
});

it('takes the first value of a multi-valued RDN attribute', function (): void {
    // OpenSSL returns an array when a name carries two CNs.
    $certificate = Certificate::fromPem(readFixture('x509/multi-cn.pem'));

    expect($certificate->commonName())->toBe('first.example')
        ->and($certificate->subject()->organization)->toBe('Crypto Test');
});

// ── validity dates (facts, never trust) ─────────────────────────────────────

it('reports its validity window', function (): void {
    $chain = TestCertificates::chain(days: 30);
    $leaf = $chain->leaf();

    expect($leaf->notAfter()->getTimestamp() - $leaf->notBefore()->getTimestamp())
        ->toBeGreaterThan(29 * 86400)
        ->and($leaf->isValidAt())->toBeTrue()
        ->and($leaf->isExpiredAt())->toBeFalse()
        ->and($leaf->isNotYetValidAt())->toBeFalse();
});

it('answers the validity predicates against an explicit instant', function (): void {
    $leaf = TestCertificates::chain(days: 30)->leaf();

    $before = $leaf->notBefore()->subHour();
    $after = $leaf->notAfter()->addHour();

    expect($leaf->isNotYetValidAt($before))->toBeTrue()
        ->and($leaf->isValidAt($before))->toBeFalse()
        ->and($leaf->isExpiredAt($before))->toBeFalse()
        ->and($leaf->isExpiredAt($after))->toBeTrue()
        ->and($leaf->isValidAt($after))->toBeFalse()
        ->and($leaf->isNotYetValidAt($after))->toBeFalse();
});

it('honours a leeway symmetrically at both bounds', function (): void {
    $leaf = TestCertificates::chain(days: 30)->leaf();
    $leeway = 300;

    // Expired by less than the leeway → still inside the widened window.
    $justExpired = $leaf->notAfter()->addSeconds(60);
    $wellExpired = $leaf->notAfter()->addSeconds(600);

    // Not yet valid by less than the leeway → also inside it. BOTH bounds move.
    $justEarly = $leaf->notBefore()->subSeconds(60);
    $wellEarly = $leaf->notBefore()->subSeconds(600);

    expect($leaf->isValidAt($justExpired, $leeway))->toBeTrue()
        ->and($leaf->isExpiredAt($justExpired, $leeway))->toBeFalse()
        ->and($leaf->isValidAt($wellExpired, $leeway))->toBeFalse()
        ->and($leaf->isExpiredAt($wellExpired, $leeway))->toBeTrue()
        ->and($leaf->isValidAt($justEarly, $leeway))->toBeTrue()
        ->and($leaf->isNotYetValidAt($justEarly, $leeway))->toBeFalse()
        ->and($leaf->isValidAt($wellEarly, $leeway))->toBeFalse()
        ->and($leaf->isNotYetValidAt($wellEarly, $leeway))->toBeTrue();
});

it('treats the bounds as inclusive with a zero leeway', function (): void {
    $leaf = TestCertificates::chain(days: 30)->leaf();

    expect($leaf->isValidAt($leaf->notBefore()))->toBeTrue()
        ->and($leaf->isValidAt($leaf->notAfter()))->toBeTrue()
        ->and($leaf->isExpiredAt($leaf->notAfter()->addSecond()))->toBeTrue()
        ->and($leaf->isNotYetValidAt($leaf->notBefore()->subSecond()))->toBeTrue();
});

it('follows Carbon test-now for the default instant', function (): void {
    // ext-openssl always stamps notBefore at signing time, so an expired
    // certificate is produced by moving the clock, not by backdating the cert.
    $leaf = TestCertificates::chain(days: 30)->leaf();

    CarbonImmutable::setTestNow($leaf->notAfter()->addDays(10));

    expect($leaf->isExpiredAt())->toBeTrue()
        ->and($leaf->isValidAt())->toBeFalse()
        ->and($leaf->isValidAt(leewaySeconds: 86400 * 11))->toBeTrue();

    CarbonImmutable::setTestNow($leaf->notBefore()->subDays(10));

    expect($leaf->isNotYetValidAt())->toBeTrue()
        ->and($leaf->isValidAt())->toBeFalse();

    CarbonImmutable::setTestNow();

    expect($leaf->isValidAt())->toBeTrue();
});

it('throws on a negative leeway from every predicate', function (): void {
    $leaf = TestCertificates::chain()->leaf();

    expect(fn (): bool => $leaf->isValidAt(null, -1))->toThrow(InvalidLeewayException::class)
        ->and(fn (): bool => $leaf->isExpiredAt(null, -1))->toThrow(InvalidLeewayException::class)
        ->and(fn (): bool => $leaf->isNotYetValidAt(null, -60))->toThrow(InvalidLeewayException::class, '-60');
});

it('gates nothing else on the dates', function (): void {
    $fixture = TestCertificates::chain(days: 30);

    CarbonImmutable::setTestNow($fixture->leaf()->notAfter()->addYear());

    // An expired certificate still hands over its key and its facts: crypto
    // reports dates, it does not rule on trust.
    expect($fixture->leaf()->isExpiredAt())->toBeTrue()
        ->and($fixture->leaf()->publicKey())->toBeInstanceOf(EcKey::class)
        ->and($fixture->leaf()->isSignedBy($fixture->chain->get(1)))->toBeTrue()
        ->and($fixture->chain->isLinked())->toBeTrue();

    CarbonImmutable::setTestNow();
});

// ── signature linkage (math, not trust) ─────────────────────────────────────

it('reports which certificate signed which', function (): void {
    $chain = TestCertificates::chain();
    [$leaf, $intermediate, $root] = $chain->chain->certificates();

    expect($leaf->isSignedBy($intermediate))->toBeTrue()
        ->and($intermediate->isSignedBy($root))->toBeTrue()
        ->and($leaf->isSignedBy($root))->toBeFalse()
        ->and($root->isSelfSigned())->toBeTrue()
        ->and($leaf->isSelfSigned())->toBeFalse()
        ->and($intermediate->isSelfSigned())->toBeFalse();
});

it('reports a stranger certificate as no signer', function (): void {
    $chain = TestCertificates::chain();
    $stranger = TestCertificates::chain();

    expect($chain->leaf()->isSignedBy($stranger->chain->get(1)))->toBeFalse()
        ->and($chain->leaf()->isSignedBy($stranger->root()))->toBeFalse();
});

it('never reports an openssl error as a clean not-signed-by', function (): void {
    // openssl_x509_verify is tri-state (1 | 0 | -1). Whatever it returns for an
    // exotic key pairing, the answer must be a bool and the error queue must be
    // drained — never a leaked warning, never a truthy -1.
    $chain = TestCertificates::chain();
    $ed25519 = Certificate::fromPem(readFixture('x509/ed25519.pem'));

    while (openssl_error_string() !== false) {
        // Start from an empty queue so what we assert about is ours.
    }

    expect($chain->leaf()->isSignedBy($ed25519))->toBeFalse()
        ->and($ed25519->isSelfSigned())->toBeBool()
        ->and(openssl_error_string())->toBeFalse();
});

// ── malformed input (no PHP warning may escape) ─────────────────────────────

it('rejects malformed certificate input with a typed exception', function (string $input): void {
    expect(fn (): Certificate => Certificate::fromPem($input))
        ->toThrow(MalformedCertificateException::class);
})->with([
    'empty' => [''],
    'garbage' => ['not a certificate at all'],
    'truncated pem' => ["-----BEGIN CERTIFICATE-----\nMIIB\n"],
    'valid header, corrupt body' => ["-----BEGIN CERTIFICATE-----\nQUJDREVGRw==\n-----END CERTIFICATE-----\n"],
    'a key, not a cert' => ["-----BEGIN PUBLIC KEY-----\nQUJD\n-----END PUBLIC KEY-----\n"],
]);

it('refuses DER carrying bytes after the certificate', function (): void {
    // Two different x5c strings must never map to one certificate: OpenSSL reads
    // the leading certificate and would silently drop the tail.
    $der = TestCertificates::selfSigned()->leaf()->der();

    expect(fn (): Certificate => Certificate::fromDer($der.'JUNK'))
        ->toThrow(MalformedCertificateException::class, 'not exactly one DER certificate')
        ->and(fn (): Certificate => Certificate::fromBase64(base64_encode($der."\x00")))
        ->toThrow(MalformedCertificateException::class, 'not exactly one DER certificate')
        ->and(Certificate::fromDer($der)->der())->toBe($der);
});

it('never reads a file:// path handed in as PEM', function (): void {
    // openssl_x509_read() treats a "file://" string as a PATH. A host passing an
    // untrusted "PEM" (a forwarded client-cert header, say) must not be able to
    // make this package read its filesystem.
    $path = tempnam(sys_get_temp_dir(), 'crypto-pem-');
    file_put_contents($path, TestCertificates::selfSigned()->leaf()->pem());

    try {
        expect(fn (): Certificate => Certificate::fromPem('file://'.$path))
            ->toThrow(MalformedCertificateException::class, 'not valid PEM')
            ->and(fn (): Chain => Chain::fromPems(['file://'.$path]))
            ->toThrow(MalformedCertificateException::class, 'not valid PEM');
    } finally {
        @unlink($path);
    }
});

it('still reads a PEM behind preamble lines, as openssl does', function (): void {
    // `openssl pkcs12` writes "Bag Attributes" lines ahead of the boundary.
    $pem = TestCertificates::selfSigned()->leaf()->pem();

    expect(Certificate::fromPem("Bag Attributes\n    localKeyID: 01\n".$pem)->der())
        ->toBe(Certificate::fromPem($pem)->der());
});

it('rejects a DER that is not a certificate', function (): void {
    expect(fn (): Certificate => Certificate::fromDer(random_bytes(64)))
        ->toThrow(MalformedCertificateException::class);
});

it('rejects an x5c entry that is not standard base64', function (): void {
    $der = TestCertificates::chain()->leaf()->der();

    expect(fn (): Certificate => Certificate::fromBase64(strtr(Base64::encode($der), '+/', '-_')))
        ->toThrow(InvalidEncodingException::class);
});

it('caps the certificate size before OpenSSL sees a byte', function (): void {
    $oversized = str_repeat('A', Certificate::MAX_CERTIFICATE_BYTES + 1);

    expect(fn (): Certificate => Certificate::fromPem($oversized))
        ->toThrow(MalformedCertificateException::class, 'over the 65536-byte cap')
        ->and(fn (): Certificate => Certificate::fromDer($oversized))
        ->toThrow(MalformedCertificateException::class, 'over the 65536-byte cap')
        ->and(fn (): Certificate => Certificate::fromBase64(str_repeat('A', 90_000)))
        ->toThrow(MalformedCertificateException::class, 'over the');
});

it('raises no PHP warning on any malformed input', function (): void {
    $raised = [];
    set_error_handler(function (int $severity, string $message) use (&$raised): bool {
        // Only a diagnostic that would actually be REPORTED counts: a call the
        // package silenced with @ still reaches the handler, with error_reporting
        // masked down. That mask is the property under test.
        if ((error_reporting() & $severity) !== 0) {
            $raised[] = $message;
        }

        return true;
    });

    foreach (['', 'garbage', str_repeat("\x00", 32), "-----BEGIN CERTIFICATE-----\n?\n-----END CERTIFICATE-----"] as $input) {
        try {
            Certificate::fromPem($input);
        } catch (MalformedCertificateException) {
            // expected
        }
    }

    restore_error_handler();

    expect($raised)->toBe([]);
});
