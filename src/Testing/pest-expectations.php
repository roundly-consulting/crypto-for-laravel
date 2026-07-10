<?php

declare(strict_types=1);

/*
 * Optional Pest expectations for consuming packages.
 *
 * This file is NOT autoloaded (it is not a class and the service provider never
 * loads it). Opt in from your own tests/Pest.php:
 *
 *     require dirname(__DIR__).'/vendor/roundly-consulting/crypto-for-laravel/src/Testing/pest-expectations.php';
 *
 * The guard keeps it inert unless Pest's expectation API is present, so it never
 * runs at package runtime.
 */

use RoundlyConsulting\Crypto\Jose\Jws;
use RoundlyConsulting\Crypto\Otp\OtpAlgorithm;
use RoundlyConsulting\Crypto\Otp\Totp;
use RoundlyConsulting\Crypto\Signature\Algorithm;
use RoundlyConsulting\Crypto\Signature\Verifier;

if (! function_exists('expect')) {
    return;
}

expect()->extend('toBeValidJws', function (Verifier $verifier, Algorithm $algorithm) {
    // Jws::verify throws on any structural, pinning, or signature failure, which
    // surfaces as a failed expectation; a returned Claims proves validity.
    $claims = (new Jws)->verify((string) $this->value, $verifier, $algorithm);

    expect($claims)->toBeInstanceOf(RoundlyConsulting\Crypto\Jose\Claims::class);

    return $this;
});

expect()->extend('toBeValidTotp', function (string $secret, ?int $timestamp = null) {
    $matched = (new Totp(OtpAlgorithm::Sha1, 6, 30))->verify($secret, (string) $this->value, 1, $timestamp);

    expect($matched)->not->toBeFalse();

    return $this;
});
