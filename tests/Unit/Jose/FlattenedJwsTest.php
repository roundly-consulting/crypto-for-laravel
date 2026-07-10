<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Jose\FlattenedJws;

it('serialises to the JWS JSON wire object', function (): void {
    $jws = new FlattenedJws('prot', 'pay', 'sig');

    expect($jws->jsonSerialize())->toBe(['protected' => 'prot', 'payload' => 'pay', 'signature' => 'sig'])
        ->and(json_encode($jws))->toBe('{"protected":"prot","payload":"pay","signature":"sig"}');
});
