<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Cose\UnsupportedAlgorithmException;
use RoundlyConsulting\Crypto\Exceptions\CryptoException;
use RoundlyConsulting\Crypto\Signature\KeyLoadException;

it('describes an export failure', function (): void {
    $exception = KeyLoadException::exportFailed();

    expect($exception)->toBeInstanceOf(CryptoException::class)
        ->and($exception->getMessage())->toContain('exported');
});

it('names the disk and path on a missing storage file', function (): void {
    expect(KeyLoadException::missingFile('local', 'keys/x.pem')->getMessage())
        ->toContain('local')
        ->toContain('keys/x.pem');
});

it('names the config key when it holds no material', function (): void {
    expect(KeyLoadException::missingConfig('jwt.secret')->getMessage())
        ->toContain('jwt.secret');
});

it('describes a missing sodium extension', function (): void {
    expect(UnsupportedAlgorithmException::sodiumMissing()->getMessage())
        ->toContain('sodium');
});
