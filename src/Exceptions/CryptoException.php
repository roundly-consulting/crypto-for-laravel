<?php

declare(strict_types=1);

namespace RoundlyConsulting\Crypto\Exceptions;

use RuntimeException;

/**
 * Base type for every exception this package throws.
 *
 * Consumers catch {@see CryptoException} to trap any crypto failure, or a more
 * specific subtype to react precisely, and typically re-wrap it as their own
 * domain exception at the package boundary.
 */
abstract class CryptoException extends RuntimeException {}
