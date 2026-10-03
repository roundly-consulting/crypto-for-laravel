<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Aead\Aes256Gcm;
use RoundlyConsulting\Crypto\Aead\DecryptionFailedException;
use RoundlyConsulting\Crypto\Aead\InvalidAeadParameterException;
use RoundlyConsulting\Crypto\Exceptions\CryptoException;
use RoundlyConsulting\Crypto\Facades\Crypto;

/*
 * AEAD_AES_256_GCM (RFC 5116 §5.2; NIST SP 800-38D): a 32-byte key, a 12-byte nonce and a
 * 16-byte tag appended to the ciphertext.
 */

/**
 * The AES-256 cases of McGrew & Viega, "The Galois/Counter Mode of Operation (GCM)",
 * Appendix B — test cases 13 to 16.
 *
 * @return array<string, array{string, string, string, string, string, string}>
 */
function gcmSpecVectors(): array
{
    $key = 'feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308';
    $nonce = 'cafebabefacedbaddecaf888';
    $plaintext = 'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255';
    $ciphertext = '522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad';

    return [
        'case 13 (empty)' => [str_repeat('00', 32), str_repeat('00', 12), '', '', '', '530f8afbc74536b9a963b4f1c4cb738b'],
        'case 14 (one zero block)' => [str_repeat('00', 32), str_repeat('00', 12), str_repeat('00', 16), '', 'cea7403d4d606b6e074ec5d3baf39d18', 'd0d1c8a799996bf0265b98b5d48ab919'],
        'case 15 (four blocks)' => [$key, $nonce, $plaintext, '', $ciphertext, 'b094dac5d93471bdec1a502270e3cc6c'],
        'case 16 (partial block, AAD)' => [$key, $nonce, substr($plaintext, 0, 120), 'feedfacedeadbeeffeedfacedeadbeefabaddad2', substr($ciphertext, 0, 120), '76fc6ece0f4e1768cddf8853bb2d551b'],
    ];
}

it('reproduces the GCM specification vectors', function (string $key, string $nonce, string $plaintext, string $aad, string $ciphertext, string $tag): void {
    $aead = new Aes256Gcm;
    $sealed = $aead->encrypt(hex2bin($key), hex2bin($nonce), (string) hex2bin($plaintext), (string) hex2bin($aad));

    expect(bin2hex($sealed))->toBe($ciphertext.$tag)
        ->and(bin2hex($aead->decrypt(hex2bin($key), hex2bin($nonce), $sealed, (string) hex2bin($aad))))->toBe($plaintext);
})->with(gcmSpecVectors());

it('matches every Wycheproof AES-256 / 96-bit nonce vector', function (): void {
    /** @var array{testGroups: list<array{keySize: int, ivSize: int, tagSize: int, tests: list<array{tcId: int, key: string, iv: string, aad: string, msg: string, ct: string, tag: string, result: string}>}>} $data */
    $data = json_decode((string) file_get_contents(__DIR__.'/../../Fixtures/wycheproof/aes_gcm_test.json'), true, 512, JSON_THROW_ON_ERROR);
    $aead = new Aes256Gcm;
    $checked = ['valid' => 0, 'invalid' => 0];

    foreach ($data['testGroups'] as $group) {
        if ($group['keySize'] !== 256 || $group['ivSize'] !== 96 || $group['tagSize'] !== 128) {
            continue;
        }

        foreach ($group['tests'] as $test) {
            $key = (string) hex2bin($test['key']);
            $nonce = (string) hex2bin($test['iv']);
            $aad = (string) hex2bin($test['aad']);
            $sealed = hex2bin($test['ct']).hex2bin($test['tag']);

            if ($test['result'] === 'valid') {
                expect(bin2hex($aead->encrypt($key, $nonce, (string) hex2bin($test['msg']), $aad)))->toBe($test['ct'].$test['tag'], "tcId {$test['tcId']}")
                    ->and(bin2hex($aead->decrypt($key, $nonce, $sealed, $aad)))->toBe($test['msg'], "tcId {$test['tcId']}");
            } else {
                expect(fn () => $aead->decrypt($key, $nonce, $sealed, $aad))->toThrow(DecryptionFailedException::class);
            }

            $checked[$test['result']]++;
        }
    }

    expect($checked)->toBe(['valid' => 39, 'invalid' => 27]);
});

it('seals with a fresh random nonce and opens only with the same key and associated data', function (): void {
    $aead = new Aes256Gcm;
    $key = random_bytes(32);
    $first = $aead->seal($key, 'secret', 'context-a');
    $second = $aead->seal($key, 'secret', 'context-a');
    $flipped = $first;
    $flipped[14] = chr(ord($flipped[14]) ^ 1);

    expect(strlen($first))->toBe(12 + 6 + 16)
        ->and(substr($first, 0, 12))->not->toBe(substr($second, 0, 12))
        ->and($aead->open($key, $first, 'context-a'))->toBe('secret')
        ->and($aead->open($key, $aead->seal($key, ''), ''))->toBe('')
        ->and(fn () => $aead->open($key, $first, 'context-b'))->toThrow(DecryptionFailedException::class)
        ->and(fn () => $aead->open(random_bytes(32), $first, 'context-a'))->toThrow(DecryptionFailedException::class)
        ->and(fn () => $aead->open($key, substr($first, 0, -1), 'context-a'))->toThrow(DecryptionFailedException::class)
        ->and(fn () => $aead->open($key, substr($first, 0, 27), 'context-a'))->toThrow(DecryptionFailedException::class)
        ->and(fn () => $aead->open($key, $flipped, 'context-a'))->toThrow(DecryptionFailedException::class);
});

it('refuses a key or nonce of the wrong length', function (): void {
    $aead = new Aes256Gcm;

    expect(fn () => $aead->encrypt(random_bytes(16), random_bytes(12), 'x'))->toThrow(InvalidAeadParameterException::class, 'key')
        ->and(fn () => $aead->encrypt(random_bytes(32), random_bytes(16), 'x'))->toThrow(InvalidAeadParameterException::class, 'nonce')
        ->and(fn () => $aead->decrypt(random_bytes(31), random_bytes(12), str_repeat("\0", 16)))->toThrow(InvalidAeadParameterException::class, 'key')
        ->and(fn () => $aead->decrypt(random_bytes(32), random_bytes(12), 'shorter than a tag'))->toThrow(DecryptionFailedException::class)
        ->and(fn () => $aead->seal('short', 'x'))->toThrow(InvalidAeadParameterException::class)
        ->and(new DecryptionFailedException)->toBeInstanceOf(CryptoException::class)
        ->and(InvalidAeadParameterException::keyLength(16))->toBeInstanceOf(CryptoException::class)
        ->and(InvalidAeadParameterException::cipherUnavailable()->getMessage())->toContain('aes-256-gcm');
});

it('never names the key or the plaintext in a failure', function (): void {
    $key = random_bytes(32);

    try {
        (new Aes256Gcm)->open($key, str_repeat("\0", 40));
    } catch (DecryptionFailedException $exception) {
        expect($exception->getMessage())->not->toContain($key)
            ->and($exception->getMessage())->toContain('authenticate');
    }
});

it('is reachable from the facade', function (): void {
    expect(Crypto::aes256Gcm())->toBeInstanceOf(Aes256Gcm::class);
});
