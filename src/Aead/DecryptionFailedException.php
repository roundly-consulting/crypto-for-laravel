<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Aead;

use RoundlyConsulting\Crypto\Exceptions\CryptoException;

/**
 * The ciphertext did not authenticate: a wrong key, nonce or associated data, or a ciphertext
 * or tag that was changed. Deliberately one message for every cause — which part failed is
 * not told.
 */
final class DecryptionFailedException extends CryptoException
{
    public function __construct()
    {
        parent::__construct('The ciphertext could not be authenticated; nothing was decrypted.');
    }
}
