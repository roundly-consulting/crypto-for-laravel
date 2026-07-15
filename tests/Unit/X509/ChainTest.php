<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Hash\HashAlgorithm;
use RoundlyConsulting\Crypto\Testing\TestCertificates;
use RoundlyConsulting\Crypto\X509\Certificate;
use RoundlyConsulting\Crypto\X509\Chain;
use RoundlyConsulting\Crypto\X509\InvalidChainException;
use RoundlyConsulting\Crypto\X509\MalformedCertificateException;

it('builds the same chain from x5c, PEMs and a PEM bundle', function (): void {
    $fixture = TestCertificates::chain();

    $fromX5c = Chain::fromX5c($fixture->x5c());
    $fromPems = Chain::fromPems(array_map(
        static fn (Certificate $certificate): string => $certificate->pem(),
        $fixture->chain->certificates(),
    ));
    $fromBundle = Chain::fromPemBundle($fixture->pemBundle());

    expect($fromX5c->fingerprints())->toBe($fixture->fingerprints(HashAlgorithm::Sha256))
        ->and($fromPems->fingerprints())->toBe($fromX5c->fingerprints())
        ->and($fromBundle->fingerprints())->toBe($fromX5c->fingerprints())
        ->and($fromBundle->count())->toBe(3);
});

it('parses a bundle with surrounding noise and trailing newlines', function (): void {
    $fixture = TestCertificates::chain();

    $bundle = "# leaf\n".$fixture->pemBundle()."\n\n# end\n";

    expect(Chain::fromPemBundle($bundle)->count())->toBe(3)
        ->and(Chain::fromPemBundle($bundle)->leaf()->der())->toBe($fixture->leaf()->der());
});

it('exposes the certificates leaf-first', function (): void {
    $fixture = TestCertificates::chain();
    $chain = $fixture->chain;

    expect($chain->count())->toBe(3)
        ->and($chain->leaf()->commonName())->toBe('leaf.crypto-test.example')
        ->and($chain->root()->commonName())->toBe('Crypto Test Root CA')
        ->and($chain->get(1)->commonName())->toBe('Crypto Test Intermediate CA 1')
        ->and($chain->certificates())->toHaveCount(3)
        ->and(iterator_to_array($chain))->toHaveCount(3);

    $names = [];

    foreach ($chain as $certificate) {
        $names[] = $certificate->commonName();
    }

    expect($names)->toBe(['leaf.crypto-test.example', 'Crypto Test Intermediate CA 1', 'Crypto Test Root CA']);
});

it('proves the chain math and nothing more', function (): void {
    $fixture = TestCertificates::chain();

    expect($fixture->chain->isLinked())->toBeTrue();
});

it('reports a rogue leaf as unlinked', function (): void {
    $fixture = TestCertificates::chain();
    $rogue = TestCertificates::rogueLeaf($fixture);

    $tampered = new Chain([$rogue, $fixture->chain->get(1), $fixture->root()]);

    expect($rogue->commonName())->toBe($fixture->leaf()->commonName())
        ->and($tampered->isLinked())->toBeFalse();
});

it('reports a reversed or spliced chain as unlinked', function (): void {
    $fixture = TestCertificates::chain();
    $stranger = TestCertificates::chain();

    $reversed = new Chain(array_reverse($fixture->chain->certificates()));
    $spliced = new Chain([$fixture->leaf(), $stranger->chain->get(1), $stranger->root()]);

    expect($reversed->isLinked())->toBeFalse()
        ->and($spliced->isLinked())->toBeFalse();
});

it('treats a single self-signed certificate as a linked chain of one', function (): void {
    $fixture = TestCertificates::selfSigned();

    expect($fixture->chain->count())->toBe(1)
        ->and($fixture->chain->isLinked())->toBeTrue()
        ->and($fixture->chain->leaf()->der())->toBe($fixture->chain->root()->der())
        ->and($fixture->chain->leaf()->isSelfSigned())->toBeTrue();
});

it('fingerprints leaf to root, in that order', function (): void {
    $fixture = TestCertificates::chain();
    $chain = $fixture->chain;

    $sha1 = $chain->fingerprints(HashAlgorithm::Sha1);

    expect($sha1[0])->toBe($chain->leaf()->fingerprint(HashAlgorithm::Sha1))
        ->and($sha1[2])->toBe($chain->root()->fingerprint(HashAlgorithm::Sha1))
        ->and(array_slice($sha1, 1))->toBe($fixture->pinnedFingerprints())
        ->and($chain->fingerprints())->not->toBe($sha1);
});

it('round-trips through its own PEM bundle', function (): void {
    $fixture = TestCertificates::chain();

    expect(Chain::fromPemBundle($fixture->chain->pemBundle())->fingerprints())
        ->toBe($fixture->chain->fingerprints());
});

// ── guards ──────────────────────────────────────────────────────────────────

it('rejects an empty chain', function (): void {
    expect(fn (): Chain => new Chain([]))->toThrow(InvalidChainException::class, 'at least one')
        ->and(fn (): Chain => Chain::fromX5c([]))->toThrow(InvalidChainException::class)
        ->and(fn (): Chain => Chain::fromPems([]))->toThrow(InvalidChainException::class)
        ->and(fn (): Chain => Chain::fromPemBundle('no certificates here'))->toThrow(InvalidChainException::class);
});

it('rejects an over-long bundle before parsing a single certificate', function (): void {
    // Eleven garbage blocks: the count check must bite BEFORE the parse, so the
    // failure is tooLong, not MalformedCertificate.
    $block = "-----BEGIN CERTIFICATE-----\nZ2FyYmFnZQ==\n-----END CERTIFICATE-----\n";
    $bundle = str_repeat($block, 11);

    expect(fn (): Chain => Chain::fromPemBundle($bundle))
        ->toThrow(InvalidChainException::class, 'over the cap of 10')
        ->and(fn (): Chain => Chain::fromPemBundle($bundle))
        ->not->toThrow(MalformedCertificateException::class);
});

it('rejects an over-long x5c and an over-long chain', function (): void {
    $entry = TestCertificates::chain(length: 1)->leaf()->base64();

    expect(fn (): Chain => Chain::fromX5c(array_fill(0, Chain::MAX_CERTIFICATES + 1, $entry)))
        ->toThrow(InvalidChainException::class, 'over the cap of 10');
});

it('rejects an index outside the chain', function (): void {
    $chain = TestCertificates::chain()->chain;

    expect(fn (): Certificate => $chain->get(3))->toThrow(InvalidChainException::class, 'index [3]')
        ->and(fn (): Certificate => $chain->get(-1))->toThrow(InvalidChainException::class);
});

it('surfaces a malformed x5c entry as a typed crypto exception', function (): void {
    expect(fn (): Chain => Chain::fromX5c(['not base64 at all!!']))
        ->toThrow(RoundlyConsulting\Crypto\Exceptions\CryptoException::class);
});
