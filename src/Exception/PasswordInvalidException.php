<?php declare(strict_types=1);

namespace Omatamix\PasswordLock\Exception;

use Exception;

/**
 * For invalid passwords.
 */
class PasswordInvalidException extends Exception implements ExceptionInterface
{
}
