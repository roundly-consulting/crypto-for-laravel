<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Facades\Crypto;
use RoundlyConsulting\Crypto\Jose\Jwk;
use RoundlyConsulting\Crypto\Signature\EdDSA;
use RoundlyConsulting\Crypto\Signature\Key\OkpKey;
use Symfony\Component\Process\Process;

/**
 * `OkpKey::publicPem()`: the Ed25519 public key as an RFC 8410 SubjectPublicKeyInfo PEM, the
 * same shape `EcKey::publicPem()` and `RsaKey::publicPem()` return.
 */

/** RFC 8410 §10.1: the example Ed25519 public key, raw and as SPKI PEM. */
const RFC8410_ED25519_PUBLIC = '19bf44096984cdfe8541bac167dc3b96c85086aa30b6b6cb0c5c38ad703166e1';

const RFC8410_ED25519_PEM = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=\n-----END PUBLIC KEY-----\n";

/**
 * Run the openssl CLI, feeding it stdin, and return what it printed.
 *
 * @param  list<string>  $arguments
 */
function opensslCli(array $arguments, string $input = ''): string
{
    $process = new Process(['openssl', ...$arguments]);
    $process->setInput($input);
    $process->mustRun();

    return $process->getOutput();
}

function opensslCliMissing(): bool
{
    $process = new Process(['openssl', 'version']);

    try {
        return $process->run() !== 0;
    } catch (Throwable) {
        return true;
    }
}

/**
 * The DER body of a PEM block.
 */
function pemBody(string $pem): string
{
    return (string) base64_decode((string) preg_replace('/-----[A-Z ]+-----|\s+/', '', $pem), true);
}

it('exports the RFC 8410 example key byte for byte', function (): void {
    $key = OkpKey::ed25519((string) hex2bin(RFC8410_ED25519_PUBLIC));

    expect($key->publicPem())->toBe(RFC8410_ED25519_PEM);
});

it('has the shape of the EC and RSA exports', function (): void {
    $pem = OkpKey::ed25519((string) hex2bin(RFC8410_ED25519_PUBLIC))->publicPem();
    $lines = explode("\n", rtrim($pem, "\n"));

    expect($pem)->toStartWith("-----BEGIN PUBLIC KEY-----\n")
        ->toEndWith("-----END PUBLIC KEY-----\n")
        ->and(array_filter($lines, static fn (string $line): bool => strlen($line) > 64))->toBe([])
        ->and(Crypto::keys()->ec()->generate()->publicPem())->toStartWith("-----BEGIN PUBLIC KEY-----\n")
        ->toEndWith("-----END PUBLIC KEY-----\n");
});

it('exports the same pem from a signing key and its public half', function (): void {
    $key = Crypto::keys()->ed25519()->generate();

    expect(Crypto::keys()->ed25519()->public($key->publicKey)->publicPem())->toBe($key->publicPem());
})->skip(fn (): bool => ! function_exists('sodium_crypto_sign_keypair'), 'ext-sodium not loaded');

it('matches openssl pkey -pubout for a key openssl generated', function (): void {
    $private = opensslCli(['genpkey', '-algorithm', 'ed25519']);
    $expected = opensslCli(['pkey', '-pubout'], $private);

    // PKCS#8 PrivateKeyInfo → privateKey OCTET STRING → CurvePrivateKey OCTET STRING: the seed.
    $decoder = Crypto::derDecoder();
    $seed = $decoder->decode($decoder->decode(pemBody($private))->children()[2]->octetString())->octetString();
    $key = OkpKey::fromSecretKey(sodium_crypto_sign_secretkey(sodium_crypto_sign_seed_keypair($seed)));

    expect($key->publicPem())->toBe($expected);
})->skip(fn (): bool => ! function_exists('sodium_crypto_sign_keypair') || opensslCliMissing(), 'needs ext-sodium and the openssl CLI');

it('matches openssl pkey -pubout for a key the package generated', function (): void {
    $key = OkpKey::generate();
    $seed = substr((string) $key->secretKey, 0, 32);

    // RFC 8410 §7: the seed as a PKCS#8 Ed25519 private key, for openssl to derive from.
    $pkcs8 = "\x30\x2e\x02\x01\x00\x30\x05\x06\x03\x2b\x65\x70\x04\x22\x04\x20".$seed;
    $private = "-----BEGIN PRIVATE KEY-----\n".chunk_split(base64_encode($pkcs8), 64, "\n")."-----END PRIVATE KEY-----\n";

    expect($key->publicPem())->toBe(opensslCli(['pkey', '-pubout'], $private));
})->skip(fn (): bool => ! function_exists('sodium_crypto_sign_keypair') || opensslCliMissing(), 'needs ext-sodium and the openssl CLI');

it('round-trips through the package\'s own loaders', function (): void {
    $key = Crypto::keys()->ed25519()->generate();
    $pem = $key->publicPem();

    $spki = Crypto::derDecoder()->decode(pemBody($pem))->children();
    $algorithm = $spki[0]->children();
    $bitString = $spki[1];

    // RFC 8410 §3: id-Ed25519 with the parameters ABSENT, then the raw key in a BIT STRING.
    expect($algorithm)->toHaveCount(1)
        ->and($algorithm[0]->oid())->toBe('1.3.101.112')
        ->and($bitString->tag)->toBe(3)
        ->and($bitString->contents[0])->toBe("\x00");

    $reloaded = Crypto::keys()->ed25519()->public(substr($bitString->contents, 1));
    $signature = Crypto::eddsa($key)->sign('deploy manifest');

    expect($reloaded->publicKey)->toBe($key->publicKey)
        ->and($reloaded->publicPem())->toBe($pem)
        ->and(Crypto::eddsa($reloaded))->toBeInstanceOf(EdDSA::class)
        ->and(Crypto::eddsa($reloaded)->verify('deploy manifest', $signature))->toBeTrue()
        ->and(Jwk::fromPublicKey($reloaded)->thumbprint())->toBe(Jwk::fromPublicKey($key)->thumbprint());
})->skip(fn (): bool => ! function_exists('sodium_crypto_sign_keypair'), 'ext-sodium not loaded');

it('reads back through ext-openssl as the same ed25519 key', function (): void {
    $raw = (string) hex2bin(RFC8410_ED25519_PUBLIC);
    $pem = OkpKey::ed25519($raw)->publicPem();
    $details = openssl_pkey_get_details(openssl_pkey_get_public($pem) ?: throw new LogicException('openssl refused the PEM'));

    expect($details)->toBeArray()
        ->and($details['type'] ?? null)->toBe(OPENSSL_KEYTYPE_ED25519)
        ->and($details['ed25519']['pub_key'] ?? null)->toBe($raw)
        ->and($details['key'] ?? null)->toBe($pem);
});
