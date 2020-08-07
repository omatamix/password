<?php declare(strict_types=1);

namespace Omatamix\PasswordLock\Exception;

use Exception;

/**
 * For the needs rehash function.
 */
class PasswordNeedsRehashException extends Exception implements ExceptionInterface
{
}
