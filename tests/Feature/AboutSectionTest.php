<?php

declare(strict_types=1);

/**
 * The secret-safe `about` capture (A).
 *
 * Purchases #13 is the bug this exists for: the fleet's most credential-heavy `about`
 * section was guarded by negative assertions against `app(Kernel::class)->output()`, which
 * returns `''`. Every "does not leak" check was vacuous; the leak was caught only because
 * one positive assertion happened to exist.
 *
 * This package's own version of that test (in PackageContractTest, which this replaces)
 * was already on the right side of it — it captured through `Artisan::output()` and wrote
 * its own "guard the guard" block. The expectation's contribution is to make that positive
 * half structurally impossible to omit: `mustRender` is a required, non-empty argument that
 * throws at call time, and it is asserted BEFORE any secret check runs.
 *
 * That matters more here than anywhere else in the fleet. Crypto is the package every
 * other one hands its keys to, and its `about` section is the one place it could
 * accidentally render them. It reads no config at all — the section reports capability
 * only — so this test's job is to keep it that way: the consumers' key material below is
 * configured, and none of it may appear.
 */
it('never renders key material, a secret, or a key path in its about section', function (): void {
    config()->set('app.key', 'base64:'.base64_encode(str_repeat('k', 32)));
    config()->set('jwt.keys.private', '/etc/roundly/secrets/jwt-signing-key.pem');
    config()->set('two-factor.pepper', 'the-pepper-value');
    config()->set('passkeys.attestation.roots', ['ac:me:tr:us:t:an:ch:or']);

    expect('crypto')->toLeakNoSecrets(
        secrets: [
            // A consumer's app key, signing-key path, pepper and trust anchor — every one
            // reachable from config, and none of crypto's business to render.
            (string) config('app.key'),
            '/etc/roundly/secrets/jwt-signing-key.pem',
            'the-pepper-value',
            'ac:me:tr:us:t:an:ch:or',
            // The two tokens that would appear if a PEM ever reached the output.
            'BEGIN',
            'PRIVATE',
        ],
        mustRender: [
            // Capability, and only capability. These are the positive proof that the
            // section rendered at all — without them every negative above is vacuous.
            'JOSE / JWS',
            'JWK / X.509',
            'enabled',
        ],
    );
});
