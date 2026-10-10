<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Hash\HashAlgorithm;
use RoundlyConsulting\Crypto\Jose\Jwk;
use RoundlyConsulting\Crypto\Signature\Key\EcKey;
use RoundlyConsulting\Crypto\Signature\Key\RsaKey;
use RoundlyConsulting\Crypto\Testing\TestCertificates;
use RoundlyConsulting\Crypto\X509\Certificate;
use RoundlyConsulting\Crypto\X509\Chain;
use RoundlyConsulting\Crypto\X509\MalformedCertificateException;

it('mints a linked three-certificate chain by default', function (): void {
    $fixture = TestCertificates::chain();

    expect($fixture->chain)->toBeInstanceOf(Chain::class)
        ->and($fixture->chain->count())->toBe(3)
        ->and($fixture->chain)->toBeLinked()
        ->and($fixture->leaf())->toBeSignedBy($fixture->chain->get(1))
        ->and($fixture->root()->isSelfSigned())->toBeTrue()
        ->and($fixture->leafKey)->toBeInstanceOf(EcKey::class);
});

it('mints a chain of any length', function (int $length): void {
    $fixture = TestCertificates::chain(length: $length);

    expect($fixture->chain->count())->toBe($length)
        ->and($fixture->chain->isLinked())->toBeTrue();
})->with([1, 2, 4]);

it('mints an RSA leaf whose private key signs for the certificate', function (): void {
    $fixture = TestCertificates::chain(leafKeyType: 'RSA');

    $signature = $fixture->leafKey->verifier()->sign('payload');

    expect($fixture->leafKey)->toBeInstanceOf(RsaKey::class)
        ->and($fixture->leaf()->publicKey())->toBeInstanceOf(RsaKey::class)
        ->and($fixture->leaf()->publicKey()->verifier()->verify('payload', $signature))->toBeTrue();
});

it('certifies a leaf key the caller already holds', function (): void {
    // A fixture whose certificate must certify a PRE-EXISTING key — an attestation
    // credential certificate, whose SPKI has to equal a key the authenticator has
    // already minted — cannot use a freshly generated one.
    $key = EcKey::generate();

    $fixture = TestCertificates::chain(length: 2, leafKey: $key);

    $certified = $fixture->leaf()->publicKey();

    expect($certified)->toBeInstanceOf(EcKey::class)
        ->and($fixture->leafKey)->toBe($key)
        ->and($fixture->chain->isLinked())->toBeTrue();

    assert($certified instanceof EcKey);

    expect($certified->coordinates()->x)->toBe($key->coordinates()->x)
        ->and($certified->coordinates()->y)->toBe($key->coordinates()->y);
});

it('certifies a supplied RSA leaf key, ignoring the key type', function (): void {
    $key = RsaKey::generate();

    $fixture = TestCertificates::chain(length: 1, leafKeyType: 'EC', leafKey: $key);

    $certified = $fixture->leaf()->publicKey();

    expect($certified)->toBeInstanceOf(RsaKey::class);

    assert($certified instanceof RsaKey);

    expect($certified->modulus())->toBe($key->modulus());
});

it('puts the requested names into subjectAltName', function (): void {
    $fixture = TestCertificates::chain(dnsNames: ['a.example', 'b.example']);

    expect($fixture->leaf()->dnsNames())->toBe(['a.example', 'b.example']);
});

it('mints a SAN-bearing self-signed certificate', function (): void {
    $fixture = TestCertificates::selfSigned(['app.test'], 'EC', 10, 'app.test');

    expect($fixture->chain->count())->toBe(1)
        ->and($fixture->leaf()->commonName())->toBe('app.test')
        ->and($fixture->leaf()->dnsNames())->toBe(['app.test'])
        ->and($fixture->leaf()->isSelfSigned())->toBeTrue()
        ->and($fixture->leafKey)->toBeInstanceOf(EcKey::class);
});

it('produces x5c entries that load back as certificates', function (): void {
    $fixture = TestCertificates::chain();

    $x5c = $fixture->x5c();

    expect($x5c)->toHaveCount(3)
        ->and(Certificate::fromBase64($x5c[0])->der())->toBe($fixture->leaf()->der())
        ->and(Chain::fromX5c($x5c)->fingerprints())->toBe($fixture->chain->fingerprints());
});

it('fingerprints like the chain it wraps: SHA-256 unless told otherwise', function (): void {
    $fixture = TestCertificates::chain();

    expect($fixture->fingerprints())->toBe($fixture->chain->fingerprints())
        ->and($fixture->pinnedFingerprints())->toBe(array_slice($fixture->chain->fingerprints(), 1))
        ->and($fixture->fingerprints(HashAlgorithm::Sha1))->toBe($fixture->chain->fingerprints(HashAlgorithm::Sha1));
});

it('exposes the pinned fingerprints as the leafless slice', function (): void {
    $fixture = TestCertificates::chain();

    expect($fixture->pinnedFingerprints())
        ->toBe(array_slice($fixture->fingerprints(), 1))
        ->and($fixture->pinnedFingerprints())->toHaveCount(2)
        ->and($fixture->pinnedFingerprints(HashAlgorithm::Sha1))
        ->toBe(array_slice($fixture->fingerprints(HashAlgorithm::Sha1), 1))
        ->and($fixture->fingerprints()[0])->toBe($fixture->leaf()->fingerprint(HashAlgorithm::Sha256));
});

it('bundles the chain as concatenated PEM', function (): void {
    $fixture = TestCertificates::chain();

    expect(Chain::fromPemBundle($fixture->pemBundle())->count())->toBe(3);
});

it('mints a rogue leaf that breaks the chain', function (): void {
    $fixture = TestCertificates::chain();
    $rogue = TestCertificates::rogueLeaf($fixture);

    expect($rogue->commonName())->toBe($fixture->leaf()->commonName())
        ->and($rogue->der())->not->toBe($fixture->leaf()->der())
        ->and($rogue->isSignedBy($fixture->chain->get(1)))->toBeFalse()
        ->and((new Chain([$rogue, $fixture->chain->get(1), $fixture->root()]))->isLinked())->toBeFalse();
});

it('mints certificates whose validity window is the requested length', function (): void {
    $fixture = TestCertificates::chain(days: 7);
    $leaf = $fixture->leaf();

    expect($leaf->isValidAt())->toBeTrue()
        ->and($leaf->notAfter()->getTimestamp() - $leaf->notBefore()->getTimestamp())
        ->toBeGreaterThanOrEqual(7 * 86400 - 60)
        ->and($leaf->isExpiredAt($leaf->notAfter()->addSecond()))->toBeTrue();
});

it('signs with its own openssl config, not the host default', function (): void {
    // The whole point of this factory: the SAN/CA sections come from a config it
    // writes itself, so a host whose default openssl.cnf lacks them still mints.
    $fixture = TestCertificates::chain(dnsNames: ['config.test']);

    // Parallel workers mint certificates too, so their in-flight configs may sit in the
    // shared temp dir right now. Ours must not linger: every config seen after the call
    // has to vanish within a moment, and a leaked one never would.
    $remaining = glob(sys_get_temp_dir().'/crypto-x509-*') ?: [];
    $deadline = microtime(true) + 2.0;

    while ($remaining !== [] && microtime(true) < $deadline) {
        usleep(10_000);
        clearstatcache();
        $remaining = array_values(array_filter($remaining, file_exists(...)));
    }

    expect($fixture->leaf()->dnsNames())->toBe(['config.test'])
        ->and($fixture->root()->signatureAlgorithm())->toBe('ecdsa-with-SHA256')
        ->and($remaining)->toBe([]);
});

it('surfaces an OpenSSL refusal as a typed exception', function (): void {
    // OpenSSL refuses a negative validity period, and refuses a CN over the
    // X.509 64-character limit. Both must be typed failures, never a warning.
    expect(fn (): mixed => TestCertificates::chain(days: -10))
        ->toThrow(MalformedCertificateException::class, 'issued')
        ->and(fn (): mixed => TestCertificates::chain(length: 1, commonName: str_repeat('a', 100)))
        ->toThrow(MalformedCertificateException::class, 'issued');
});

it('supplies a thumbprint expectation for JWKs', function (): void {
    $jwk = Jwk::fromPublicKey(EcKey::private(keyPem('acme-account-ec')));

    expect($jwk)->toHaveThumbprint('DpAbuSaUplaRVIlOVIuqaTx0TmbkHsJ0Ww75jvLVhnQ')
        ->and($jwk)->toHaveThumbprint($jwk->thumbprint(HashAlgorithm::Sha384), HashAlgorithm::Sha384);
});
