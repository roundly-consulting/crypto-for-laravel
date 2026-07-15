<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Exceptions\CryptoException;
use RoundlyConsulting\Crypto\X509\Certificate;
use RoundlyConsulting\Crypto\X509\InvalidChainException;
use RoundlyConsulting\Crypto\X509\InvalidLeewayException;
use RoundlyConsulting\Crypto\X509\MalformedCertificateException;

/*
 * An exception whose message does not say what is wrong is a support ticket. Pin
 * the diagnosis in each one.
 */

it('describes every certificate failure', function (): void {
    expect(MalformedCertificateException::unreadable())->toBeInstanceOf(CryptoException::class)
        ->and(MalformedCertificateException::unreadable()->getMessage())->toContain('PEM or DER')
        ->and(MalformedCertificateException::unparseable()->getMessage())->toContain('could not be parsed')
        ->and(MalformedCertificateException::exportFailed()->getMessage())->toContain('exported')
        ->and(MalformedCertificateException::issuanceFailed()->getMessage())->toContain('issued')
        ->and(MalformedCertificateException::unsupportedKeyType()->getMessage())->toContain('RSA or EC')
        ->and(MalformedCertificateException::tooLarge(70_000, Certificate::MAX_CERTIFICATE_BYTES)->getMessage())
        ->toContain('70000')
        ->toContain('65536');
});

it('describes every chain failure', function (): void {
    expect(InvalidChainException::empty()->getMessage())->toContain('at least one')
        ->and(InvalidChainException::tooLong(11)->getMessage())->toContain('11')->toContain('10')
        ->and(InvalidChainException::outOfRange(7)->getMessage())->toContain('[7]');
});

it('names the offending leeway', function (): void {
    expect(InvalidLeewayException::negative(-30))->toBeInstanceOf(CryptoException::class)
        ->and(InvalidLeewayException::negative(-30)->getMessage())->toContain('-30');
});
