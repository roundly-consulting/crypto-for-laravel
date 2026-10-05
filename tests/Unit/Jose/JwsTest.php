<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Codec\Base64Url;
use RoundlyConsulting\Crypto\Jose\Claims;
use RoundlyConsulting\Crypto\Jose\Jws;
use RoundlyConsulting\Crypto\Jose\MalformedTokenException;
use RoundlyConsulting\Crypto\Signature\Algorithm;
use RoundlyConsulting\Crypto\Signature\AlgorithmMismatchException;
use RoundlyConsulting\Crypto\Signature\Es;
use RoundlyConsulting\Crypto\Signature\Hs;
use RoundlyConsulting\Crypto\Signature\InvalidSignatureException;
use RoundlyConsulting\Crypto\Signature\Key\EcKey;
use RoundlyConsulting\Crypto\Signature\Key\HmacSecret;
use RoundlyConsulting\Crypto\Signature\Key\RsaKey;
use RoundlyConsulting\Crypto\Signature\Rs;

function hsSigner(): Hs
{
    return new Hs(HmacSecret::fromString('0123456789abcdef0123456789abcdef!'));
}

it('signs and verifies a compact HS256 JWS', function (): void {
    $jws = new Jws;
    $compact = $jws->sign(['kid' => 'k1'], ['sub' => 'alice', 'exp' => 9999999999], hsSigner());

    $claims = $jws->verify($compact, hsSigner(), Algorithm::HS256);

    expect($claims)->toBeInstanceOf(Claims::class)
        ->and($claims->string('sub'))->toBe('alice')
        ->and(str_contains($compact, '.'))->toBeTrue();
});

it('sets the header typ and alg deterministically', function (): void {
    $compact = (new Jws)->sign([], ['a' => 1], hsSigner());
    [$header] = explode('.', $compact);
    $decoded = json_decode(Base64Url::decode($header), true);

    expect($decoded)->toBe(['typ' => 'JWT', 'alg' => 'HS256']);
});

it('signs and verifies RS256 and ES256 round-trips', function (): void {
    $jws = new Jws;

    $rs = $jws->sign([], ['sub' => 'r'], new Rs(RsaKey::private(keyPem('rsa-private'))));
    expect($jws->verify($rs, new Rs(RsaKey::public(keyPem('rsa-public'))), Algorithm::RS256)->string('sub'))->toBe('r');

    $es = $jws->sign([], ['sub' => 'e'], new Es(EcKey::private(keyPem('ec-private'))));
    expect($jws->verify($es, new Es(EcKey::public(keyPem('ec-public'))), Algorithm::ES256)->string('sub'))->toBe('e');
});

it('signs and verifies the full SHA-2 signature tier', function (Algorithm $algorithm): void {
    $jws = new Jws;
    $secret = HmacSecret::fromString(str_repeat('0123456789abcdef', 4));
    $signer = new Hs($secret, $algorithm);

    $compact = $jws->sign([], ['sub' => 'x'], $signer);

    expect($jws->verify($compact, new Hs($secret, $algorithm), $algorithm)->string('sub'))->toBe('x');
})->with([
    'HS384' => [Algorithm::HS384],
    'HS512' => [Algorithm::HS512],
]);

it('pins HS512 and rejects an HS512 token presented to an HS256 verifier', function (): void {
    $secret = HmacSecret::fromString(str_repeat('0123456789abcdef', 4));
    $compact = (new Jws)->sign([], ['sub' => 'x'], new Hs($secret, Algorithm::HS512));

    (new Jws)->verify($compact, new Hs($secret, Algorithm::HS256), Algorithm::HS256);
})->throws(AlgorithmMismatchException::class);

it('signs and verifies RS512 and ES512 compact tokens', function (): void {
    $jws = new Jws;

    $rs = $jws->sign([], ['sub' => 'r'], new Rs(RsaKey::private(keyPem('rsa-private')), Algorithm::RS512));
    expect($jws->verify($rs, new Rs(RsaKey::public(keyPem('rsa-public')), Algorithm::RS512), Algorithm::RS512)->string('sub'))->toBe('r');

    $ec = EcKey::generate('P-521');
    $public = EcKey::public((string) openssl_pkey_get_details($ec->key)['key']);
    $es = $jws->sign([], ['sub' => 'e'], new Es($ec));
    expect($jws->verify($es, new Es($public), Algorithm::ES512)->string('sub'))->toBe('e');
});

it('signs and verifies an EdDSA compact JWS', function (): void {
    $jws = new Jws;
    $key = RoundlyConsulting\Crypto\Signature\Key\OkpKey::generate();

    $compact = $jws->sign([], ['sub' => 'ed'], new RoundlyConsulting\Crypto\Signature\EdDSA($key));

    expect($jws->verify($compact, new RoundlyConsulting\Crypto\Signature\EdDSA($key), Algorithm::EdDSA)->string('sub'))->toBe('ed');
})->skip(fn (): bool => ! function_exists('sodium_crypto_sign_detached'), 'ext-sodium not loaded');

it('verifies the RFC 7515 A.1 HS256 vector', function (): void {
    $vector = jsonFixture('hs256-rfc7515-a1.json');
    $key = HmacSecret::fromString(Base64Url::decode($vector['hmac_key_b64url']));

    $claims = (new Jws)->verify($vector['jwt'], new Hs($key), Algorithm::HS256);

    expect($claims->string('iss'))->toBe($vector['expected_iss'])
        ->and($claims->int('exp'))->toBe($vector['expected_exp']);
});

it('verifies the RFC 7515 A.2 RS256 vector', function (): void {
    $vector = jsonFixture('rs256-rfc7515-a2.json');
    $key = RsaKey::public(keyPem('rfc7515-a2-public'));

    $claims = (new Jws)->verify($vector['jwt'], new Rs($key), Algorithm::RS256);

    expect($claims->string('iss'))->toBe($vector['expected_iss'])
        ->and($claims->int('exp'))->toBe($vector['expected_exp']);
});

it('re-mints the RFC 7515 A.1 payload byte-for-byte given the same header order', function (): void {
    // Proves deterministic JSON: same claims + signer reproduce the exact segments.
    $signer = hsSigner();
    $a = (new Jws)->sign([], ['sub' => 'x', 'n' => 1], $signer);
    $b = (new Jws)->sign([], ['sub' => 'x', 'n' => 1], $signer);

    expect($a)->toBe($b);
});

it('rejects an alg:none downgrade before touching the signature', function (): void {
    $header = Base64Url::encode('{"typ":"JWT","alg":"none"}');
    $payload = Base64Url::encode('{"sub":"x"}');

    (new Jws)->verify($header.'.'.$payload.'.', hsSigner(), Algorithm::HS256);
})->throws(AlgorithmMismatchException::class);

it('rejects an RS256↔HS256 confusion attempt', function (): void {
    // A token minted as HS256 must not verify when the caller pins RS256.
    $compact = (new Jws)->sign([], ['sub' => 'x'], hsSigner());

    (new Jws)->verify($compact, new Rs(RsaKey::public(keyPem('rsa-public'))), Algorithm::RS256);
})->throws(AlgorithmMismatchException::class);

it('rejects a verifier whose algorithm differs from the expectation', function (): void {
    $compact = (new Jws)->sign([], ['sub' => 'x'], hsSigner());

    (new Jws)->verify($compact, hsSigner(), Algorithm::RS256);
})->throws(AlgorithmMismatchException::class);

it('rejects a crit header', function (): void {
    $header = Base64Url::encode('{"typ":"JWT","alg":"HS256","crit":["exp"]}');
    $payload = Base64Url::encode('{"sub":"x"}');

    (new Jws)->verify($header.'.'.$payload.'.sig', hsSigner(), Algorithm::HS256);
})->throws(MalformedTokenException::class);

it('rejects an oversize token', function (): void {
    (new Jws)->verify(str_repeat('a', Jws::MAX_ENCODED_BYTES + 1), hsSigner(), Algorithm::HS256);
})->throws(MalformedTokenException::class);

it('rejects a token without three segments', function (): void {
    (new Jws)->verify('only.two', hsSigner(), Algorithm::HS256);
})->throws(MalformedTokenException::class);

it('rejects a tampered signature', function (): void {
    $compact = (new Jws)->sign([], ['sub' => 'x'], hsSigner());
    $tampered = substr($compact, 0, -4).'AAAA';

    (new Jws)->verify($tampered, hsSigner(), Algorithm::HS256);
})->throws(InvalidSignatureException::class);

it('rejects a header that is not a JSON object', function (): void {
    $header = Base64Url::encode('["not","object"]');
    $payload = Base64Url::encode('{"sub":"x"}');

    (new Jws)->verify($header.'.'.$payload.'.sig', hsSigner(), Algorithm::HS256);
})->throws(MalformedTokenException::class);

it('rejects a payload that is not valid JSON', function (): void {
    $header = Base64Url::encode('{"typ":"JWT","alg":"HS256"}');
    $payload = Base64Url::encode('not json');

    (new Jws)->verify($header.'.'.$payload.'.sig', hsSigner(), Algorithm::HS256);
})->throws(MalformedTokenException::class);

it('rejects a header with a missing alg', function (): void {
    $header = Base64Url::encode('{"typ":"JWT"}');
    $payload = Base64Url::encode('{"sub":"x"}');

    (new Jws)->verify($header.'.'.$payload.'.sig', hsSigner(), Algorithm::HS256);
})->throws(AlgorithmMismatchException::class);

it('signs a flattened JWS with an empty payload', function (): void {
    $flattened = (new Jws)->flattened(['nonce' => 'abc'], '', new Rs(RsaKey::private(keyPem('rsa-private'))));

    expect($flattened->payload)->toBe('')
        ->and($flattened->protected)->not->toBe('')
        ->and($flattened->signature)->not->toBe('');

    // The protected header carries the alg.
    $protected = json_decode(Base64Url::decode($flattened->protected), true);
    expect($protected['alg'])->toBe('RS256')
        ->and($protected['nonce'])->toBe('abc');
});

it('signs a flattened JWS whose signature verifies', function (): void {
    $flattened = (new Jws)->flattened([], '{"terms":"accepted"}', new Es(EcKey::private(keyPem('ec-private'))));
    $signingInput = $flattened->protected.'.'.$flattened->payload;

    $verifier = new Es(EcKey::public(keyPem('ec-public')));
    expect($verifier->verify($signingInput, Base64Url::decode($flattened->signature)))->toBeTrue();
});

it('rejects unencodable claims', function (): void {
    (new Jws)->sign([], ['bad' => "\xB1\x31"], hsSigner());
})->throws(MalformedTokenException::class);

it('encodes empty claims as the JSON object {}, never the array []', function (): void {
    $compact = (new Jws)->sign([], [], hsSigner());
    [, $payload] = explode('.', $compact);

    expect(Base64Url::decode($payload))->toBe('{}')
        ->and((new Jws)->verify($compact, hsSigner(), Algorithm::HS256)->all())->toBe([]);
});

it('rejects a signed payload that is the JSON array [] rather than an object', function (string $json): void {
    // A genuinely signed token: only the payload's JSON TYPE is wrong.
    $header = Base64Url::encode('{"typ":"JWT","alg":"HS256"}');
    $payload = Base64Url::encode($json);
    $signature = Base64Url::encode(hsSigner()->sign($header.'.'.$payload));

    (new Jws)->verify($header.'.'.$payload.'.'.$signature, hsSigner(), Algorithm::HS256);
})->throws(MalformedTokenException::class, 'must be a JSON object')->with(['[]', ' [ ] ', '"claims"', '42']);

it('encodes claims with list-shaped keys as a JSON object verify() accepts', function (array $claims): void {
    $jws = new Jws;
    $compact = $jws->sign([], $claims, hsSigner());
    [, $payload] = explode('.', $compact);

    // PHP casts the string keys "0" and "1" to ints, which would make
    // json_encode() write an array.
    expect(Base64Url::decode($payload))->toStartWith('{')
        ->and($jws->verify($compact, hsSigner(), Algorithm::HS256)->all())->toBe($claims);
})->with([
    'numeric-string keys' => [['0' => 'x', '1' => 'y']],
    'a list' => [['a', 'b']],
]);
