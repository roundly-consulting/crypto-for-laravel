<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Testing;

use OpenSSLAsymmetricKey;
use OpenSSLCertificateSigningRequest;
use RoundlyConsulting\Crypto\Signature\Key\EcKey;
use RoundlyConsulting\Crypto\Signature\Key\RsaKey;
use RoundlyConsulting\Crypto\Signature\OpenSsl;
use RoundlyConsulting\Crypto\X509\Certificate;
use RoundlyConsulting\Crypto\X509\Chain;
use RoundlyConsulting\Crypto\X509\MalformedCertificateException;
use RoundlyConsulting\Crypto\X509\OpenSslX509;

/**
 * Throwaway X.509 certificate chains for a consuming package's own test suite —
 * the {@see TestKeys} counterpart for certificates.
 *
 * Minting a chain by hand means CSRs, a CA extension section, and an `openssl.cnf`
 * that actually carries the sections you need — which many hosts' default config
 * does not (Herd's PHP resolves an `openssl.cnf` with no EC sections at all).
 * This class writes its own temporary config, so it works on a host whose default
 * config is unusable, and every consumer stops re-solving it.
 *
 * These ship in `src/` (runtime autoload) but pull in no PHPUnit/Pest symbol.
 * Certificates are built through the real {@see Certificate}/{@see Chain} API, so
 * this doubles as an integration exercise of the X.509 module.
 *
 * **Validity dates.** `ext-openssl` always stamps `notBefore` at the moment of
 * signing and refuses a negative validity period — PHP's API exposes no way to
 * backdate or postdate a certificate. So expired and not-yet-valid fixtures are
 * made by evaluating a normal certificate at another instant:
 *
 *     $leaf->isExpiredAt($leaf->notAfter()->addDay());        // expired
 *     $leaf->isNotYetValidAt($leaf->notBefore()->subDay());   // not yet valid
 *     CarbonImmutable::setTestNow($leaf->notAfter()->addYear());
 *
 * which is exactly what the `$at` parameter on the validity predicates is for,
 * and is deterministic where a wall-clock fixture would not be. `$days` sets the
 * window's length; OpenSSL refuses a negative one, which surfaces as a
 * {@see MalformedCertificateException} rather than a silently odd certificate.
 */
final class TestCertificates
{
    /**
     * A fresh throwaway chain, leaf → … → root ($length certificates, default 3,
     * i.e. leaf → intermediate → root). CA keys are EC P-256; the leaf's key type
     * is `EC` or `RSA`. `$days` is the validity window's length — see the class
     * docblock for how to test expiry.
     *
     * @param  list<string>  $dnsNames
     *
     * @throws MalformedCertificateException|\RoundlyConsulting\Crypto\Signature\KeyLoadException|\RoundlyConsulting\Crypto\Signature\WeakKeyException
     */
    public static function chain(
        int $length = 3,
        string $leafKeyType = 'EC',
        string $commonName = 'leaf.crypto-test.example',
        array $dnsNames = [],
        int $days = 365,
    ): TestCertificateChain {
        $length = max(1, $length);
        $leafKey = self::key($leafKeyType);

        // The root signs itself; each certificate below it is signed by the one
        // above, so the chain is genuinely linked rather than merely ordered.
        $issuerKey = null;
        $issuerPem = null;
        $certificates = [];

        for ($depth = $length - 1; $depth >= 0; $depth--) {
            $key = $depth === 0 ? $leafKey : EcKey::generate();

            $pem = self::issue(
                key: $key->key,
                commonName: $depth === 0 ? $commonName : self::authorityName($depth, $length),
                dnsNames: $depth === 0 ? $dnsNames : [],
                isAuthority: $depth > 0,
                issuerKey: $issuerKey,
                issuerPem: $issuerPem,
                days: $days,
            );

            $issuerKey = $key->key;
            $issuerPem = $pem;

            // Built root-first; the chain is leaf-first.
            array_unshift($certificates, Certificate::fromPem($pem));
        }

        return new TestCertificateChain(new Chain($certificates), $leafKey);
    }

    /**
     * A single SAN-bearing self-signed certificate and its key.
     *
     * @param  list<string>  $dnsNames
     *
     * @throws MalformedCertificateException|\RoundlyConsulting\Crypto\Signature\KeyLoadException|\RoundlyConsulting\Crypto\Signature\WeakKeyException
     */
    public static function selfSigned(
        array $dnsNames = ['crypto-test.example'],
        string $keyType = 'RSA',
        int $days = 90,
        string $commonName = 'crypto-test.example',
    ): TestCertificateChain {
        $key = self::key($keyType);

        $pem = self::issue(
            key: $key->key,
            commonName: $commonName,
            dnsNames: $dnsNames,
            isAuthority: false,
            issuerKey: null,
            issuerPem: null,
            days: $days,
        );

        return new TestCertificateChain(new Chain([Certificate::fromPem($pem)]), $key);
    }

    /**
     * A leaf carrying the same subject as $chain's leaf but signed by a DIFFERENT
     * throwaway authority — the rogue-leaf fixture every pinning test needs.
     *
     * @throws MalformedCertificateException|\RoundlyConsulting\Crypto\Signature\KeyLoadException|\RoundlyConsulting\Crypto\Signature\WeakKeyException
     */
    public static function rogueLeaf(TestCertificateChain $chain): Certificate
    {
        $rogue = self::chain(
            length: 2,
            commonName: $chain->leaf()->commonName() ?? 'leaf.crypto-test.example',
            dnsNames: $chain->leaf()->dnsNames(),
        );

        return $rogue->leaf();
    }

    /**
     * @throws \RoundlyConsulting\Crypto\Signature\KeyLoadException|\RoundlyConsulting\Crypto\Signature\WeakKeyException
     */
    private static function key(string $type): EcKey|RsaKey
    {
        return $type === 'RSA' ? RsaKey::generate() : EcKey::generate();
    }

    private static function authorityName(int $depth, int $length): string
    {
        return $depth === $length - 1
            ? 'Crypto Test Root CA'
            : "Crypto Test Intermediate CA {$depth}";
    }

    /**
     * Issue a certificate for $key, signed by $issuerKey (or self-signed when no
     * issuer is given), and return its PEM.
     *
     * @param  list<string>  $dnsNames
     *
     * @throws MalformedCertificateException
     */
    private static function issue(
        OpenSSLAsymmetricKey $key,
        string $commonName,
        array $dnsNames,
        bool $isAuthority,
        ?OpenSSLAsymmetricKey $issuerKey,
        ?string $issuerPem,
        int $days,
    ): string {
        $config = self::writeConfig($dnsNames);

        try {
            $options = [
                'config' => $config,
                'digest_alg' => 'sha256',
                'x509_extensions' => $isAuthority ? 'v3_ca' : 'v3_leaf',
            ];

            $csr = @openssl_csr_new(
                ['commonName' => $commonName, 'organizationName' => 'Crypto Test', 'countryName' => 'SK'],
                $key,
                $options,
            );

            if (! $csr instanceof OpenSSLCertificateSigningRequest) {
                OpenSsl::drainErrors();

                throw MalformedCertificateException::issuanceFailed();
            }

            $certificate = @openssl_csr_sign(
                $csr,
                $issuerPem,
                $issuerKey ?? $key,
                $days,
                $options,
                random_int(1, PHP_INT_MAX),
            );

            if ($certificate === false) {
                OpenSsl::drainErrors();

                throw MalformedCertificateException::issuanceFailed();
            }

            return OpenSslX509::exportPem($certificate);
        } finally {
            @unlink($config);
        }
    }

    /**
     * Write the temporary `openssl.cnf` this class signs against.
     *
     * The host's default config is not trusted: it commonly lacks the `req` and
     * `v3_*` sections (and, on some PHP builds, EC support entirely), which is the
     * exact failure every consumer has been working around by probing three
     * candidate paths.
     *
     * @param  list<string>  $dnsNames
     */
    private static function writeConfig(array $dnsNames): string
    {
        $alt = '';

        foreach ($dnsNames as $index => $name) {
            $alt .= 'DNS.'.($index + 1)." = {$name}\n";
        }

        $san = $dnsNames === [] ? '' : "subjectAltName = @alt_names\n";

        $config = <<<CNF
            [ req ]
            distinguished_name = dn
            prompt = no

            [ dn ]

            [ v3_ca ]
            basicConstraints = critical,CA:TRUE
            keyUsage = critical,keyCertSign,cRLSign
            subjectKeyIdentifier = hash

            [ v3_leaf ]
            basicConstraints = critical,CA:FALSE
            keyUsage = critical,digitalSignature
            extendedKeyUsage = serverAuth
            subjectKeyIdentifier = hash
            {$san}
            [ alt_names ]
            {$alt}
            CNF;

        $path = (string) tempnam(sys_get_temp_dir(), 'crypto-x509-');

        file_put_contents($path, $config);

        return $path;
    }
}
