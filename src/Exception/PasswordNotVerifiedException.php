<?php declare(strict_types=1);

namespace Omatamix\PasswordLock\Exception;

use Exception;

/**
 * For the verify hash function.
 */
class PasswordNotVerifiedException extends Exception implements ExceptionInterface
{
}
