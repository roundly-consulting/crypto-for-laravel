<?php

declare(strict_types=1);

/**
 * `#[SensitiveParameter]` works per FRAME: PHP redacts an argument only in the frame of the
 * function that marks it. A secret that passes through one unmarked frame (a codec, the
 * constant-time compare, a private helper) is back in plain text in every stack trace captured
 * below it: exception traces, error reporters, `debug_backtrace()`.
 *
 * The rule: a parameter is marked when it carries key material, a secret, a pepper, an OTP
 * secret or code, plaintext to encrypt, a value compared in constant time, a bearer token, or
 * the input of a codec or digest (the package routes OTP secrets, token bytes, keys, passwords
 * and tokens through those). It is NOT marked for messages to sign or MAC, ciphertext, nonces,
 * associated data, public keys, certificates, signatures checked with a public key, or
 * algorithm / length / label / issuer / disk / path / config-key arguments.
 *
 * Pinned three ways:
 *
 *  1. every parameter on the list carries the attribute (drop one and this goes red);
 *  2. every marked parameter in src/ is on the list, so a new mark is a reviewed decision;
 *  3. every parameter NAMED like a secret carries it, so a new `$secret` cannot forget it.
 *
 * @return list<string>
 */
function expectedSensitiveParameters(): array
{
    return [
        'Aead\Aes256Gcm::assertParameters($key)',
        'Aead\Aes256Gcm::decrypt($key)',
        'Aead\Aes256Gcm::encrypt($key)',
        'Aead\Aes256Gcm::encrypt($plaintext)',
        'Aead\Aes256Gcm::open($key)',
        'Aead\Aes256Gcm::seal($key)',
        'Aead\Aes256Gcm::seal($plaintext)',
        'Codec\Base32::decode($base32)',
        'Codec\Base32::encode($bytes)',
        'Codec\Base64::decode($text)',
        'Codec\Base64::encode($bytes)',
        'Codec\Base64Url::decode($text)',
        'Codec\Base64Url::encode($bytes)',
        'Codec\Hex::decode($hex)',
        'Codec\Hex::encode($bytes)',
        'CryptoManager::base32Decode($base32)',
        'CryptoManager::base32Encode($bytes)',
        'CryptoManager::base64Decode($text)',
        'CryptoManager::base64Encode($bytes)',
        'CryptoManager::base64UrlDecode($text)',
        'CryptoManager::base64UrlEncode($bytes)',
        'CryptoManager::constantTimeEquals($known)',
        'CryptoManager::constantTimeEquals($user)',
        'CryptoManager::hexDecode($hex)',
        'CryptoManager::hexEncode($bytes)',
        'CryptoManager::provisioningUri($secret)',
        'Hash\ConstantTime::equals($known)',
        'Hash\ConstantTime::equals($user)',
        'Hash\Digest::hex($data)',
        'Hash\Digest::raw($data)',
        'Hash\Digest::withPepper($data)',
        'Hash\Digest::withPepper($pepper)',
        'Hash\Hmac::sign($key)',
        'Hash\Hmac::signHex($key)',
        'Hash\Hmac::verify($key)',
        'Hash\Hmac::verify($signature)',
        'Jose\Jws::verify($compact)',
        'Otp\Hotp::at($secret)',
        'Otp\ProvisioningUri::totp($secret)',
        'Otp\Totp::at($secret)',
        'Otp\Totp::codeAt($secret)',
        'Otp\Totp::isWellFormed($code)',
        'Otp\Totp::verify($code)',
        'Otp\Totp::verify($secret)',
        'Random\Secret::canonicalize($secret)',
        'Signature\Hs::verify($signature)',
        'Signature\Key\EcKey::private($pem)',
        'Signature\Key\EcKeys::private($pem)',
        'Signature\Key\Ed25519Keys::private($secretKey)',
        'Signature\Key\HmacSecret::__construct($value)',
        'Signature\Key\HmacSecret::carriesKeyMaterial($secret)',
        'Signature\Key\HmacSecret::fromString($secret)',
        'Signature\Key\HmacSecrets::fromString($secret)',
        'Signature\Key\OkpKey::__construct($secretKey)',
        'Signature\Key\OkpKey::fromSecretKey($secretKey)',
        'Signature\Key\ReadsKeyMaterial::persistPrivate($contents)',
        'Signature\Key\ReadsKeyMaterial::requireConfigString($value)',
        'Signature\Key\ReadsKeyMaterial::wipeSecret($secret)',
        'Signature\Key\ReadsKeyMaterial::writeLocalAtomically($contents)',
        'Signature\Key\RsaKey::private($pem)',
        'Signature\Key\RsaKeys::private($pem)',
        'Signature\OpenSsl::isPemText($input)',
    ];
}

/**
 * Parameter names that only ever mean secret material in this package.
 *
 * @return list<string>
 */
function secretParameterNames(): array
{
    return [
        'code', 'compact', 'known', 'passphrase', 'password', 'pepper', 'plaintext',
        'secret', 'secretKey', 'seed', 'token', 'user',
    ];
}

/**
 * Every parameter of every method in src/, keyed `Class::method($param)` relative to the
 * package namespace, mapped to whether it carries the attribute. A trait's methods are
 * reported once, on the trait, not again on each class that uses it.
 *
 * @return array<string, bool>
 */
function sensitiveParameterInventory(): array
{
    $root = realpath(__DIR__.'/../../src');
    $inventory = [];

    foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator((string) $root)) as $file) {
        $path = (string) $file;

        if (! str_ends_with($path, '.php') || preg_match('/^[A-Z]/', basename($path)) !== 1) {
            continue;
        }

        $relative = str_replace('/', '\\', substr($path, strlen((string) $root) + 1, -4));
        $class = new ReflectionClass('RoundlyConsulting\\Crypto\\'.$relative);

        foreach ($class->getMethods() as $method) {
            if ($method->getDeclaringClass()->getName() !== $class->getName() || $method->getFileName() !== $class->getFileName()) {
                continue;
            }

            foreach ($method->getParameters() as $parameter) {
                $key = "{$relative}::{$method->getName()}(\${$parameter->getName()})";
                $inventory[$key] = $parameter->getAttributes(SensitiveParameter::class) !== [];
            }
        }
    }

    ksort($inventory);

    return $inventory;
}

it('marks every listed secret parameter sensitive', function (): void {
    $inventory = sensitiveParameterInventory();

    foreach (expectedSensitiveParameters() as $parameter) {
        expect($inventory)->toHaveKey($parameter)
            ->and($inventory[$parameter])->toBeTrue("{$parameter} lost #[SensitiveParameter]");
    }
});

it('marks nothing beyond the reviewed list', function (): void {
    $marked = array_keys(array_filter(sensitiveParameterInventory()));
    $expected = expectedSensitiveParameters();
    sort($expected);

    expect($marked)->toBe($expected);
});

it('marks every parameter named like a secret', function (): void {
    $unmarked = array_keys(array_filter(
        sensitiveParameterInventory(),
        static fn (bool $sensitive, string $key): bool => ! $sensitive
            && preg_match('/\(\$('.implode('|', secretParameterNames()).')\)$/', $key) === 1,
        ARRAY_FILTER_USE_BOTH,
    ));

    expect($unmarked)->toBe([]);
});

it('takes its inventory from the real source tree', function (): void {
    // Non-vacuous: an empty or broken scan would pass the three checks above.
    expect(count(sensitiveParameterInventory()))->toBeGreaterThan(300)
        ->and(expectedSensitiveParameters())->not->toBeEmpty();
});
