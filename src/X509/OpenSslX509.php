<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\X509;

use OpenSSLAsymmetricKey;
use OpenSSLCertificate;
use RoundlyConsulting\Crypto\Signature\OpenSsl;

/**
 * The X.509 OpenSSL gateway, mirroring {@see OpenSsl}.
 *
 * Certificate bytes are attacker-controlled — an `x5c` header is whatever the
 * token said — so every `openssl_x509_*` call the package makes goes through
 * here: silenced, with the OpenSSL error queue drained and the failure converted
 * into a typed exception. A malformed certificate must never surface a PHP
 * warning.
 *
 * @internal
 */
final class OpenSslX509
{
    /**
     * @throws MalformedCertificateException
     */
    public static function read(string $pem): OpenSSLCertificate
    {
        $certificate = @openssl_x509_read($pem);

        if ($certificate === false) {
            OpenSsl::drainErrors();

            throw MalformedCertificateException::unreadable();
        }

        return $certificate;
    }

    /**
     * The parsed certificate fields. Short names (`CN`, `O`, …) are requested, as
     * every consumer of this data reads short names.
     *
     * @return array<string, mixed>
     *
     * @throws MalformedCertificateException
     */
    public static function parse(OpenSSLCertificate $certificate): array
    {
        $parsed = @openssl_x509_parse($certificate, true);

        if ($parsed === false) {
            OpenSsl::drainErrors();

            throw MalformedCertificateException::unparseable();
        }

        return $parsed;
    }

    /**
     * The canonical PEM for a certificate handle.
     *
     * @throws MalformedCertificateException
     */
    public static function exportPem(OpenSSLCertificate $certificate): string
    {
        $pem = '';

        if (@openssl_x509_export($certificate, $pem) === false) {
            OpenSsl::drainErrors();

            throw MalformedCertificateException::exportFailed();
        }

        return $pem;
    }

    /**
     * The certificate's public key, as OpenSSL's key details.
     *
     * A certificate whose SPKI names an algorithm OpenSSL cannot load fails here
     * — one typed exception, whichever of the two steps refused it.
     *
     * @return array<string, mixed>
     *
     * @throws MalformedCertificateException
     */
    public static function publicKeyDetails(OpenSSLCertificate $certificate): array
    {
        $key = @openssl_pkey_get_public($certificate);
        $details = $key instanceof OpenSSLAsymmetricKey ? @openssl_pkey_get_details($key) : false;

        if ($details === false) {
            OpenSsl::drainErrors();

            throw MalformedCertificateException::unsupportedKeyType();
        }

        return $details;
    }

    /**
     * Whether the certificate's signature was made by the issuer's key.
     *
     * `openssl_x509_verify()` is tri-state: `1` signed, `0` not signed, and `-1`
     * an ERROR (an unsupported signature algorithm, a key it cannot use). Only an
     * exact `1` is true; `-1` drains the error queue and reports false, so an
     * error is never mistaken for a clean "not signed by" — the same discipline
     * {@see OpenSsl::verify()} applies to `openssl_verify`.
     */
    public static function signatureMatches(OpenSSLCertificate $certificate, OpenSSLCertificate $issuer): bool
    {
        $result = @openssl_x509_verify($certificate, $issuer);

        if ($result === -1) {
            OpenSsl::drainErrors();
        }

        return $result === 1;
    }
}
