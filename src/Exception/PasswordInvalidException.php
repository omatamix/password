<?php
declare(strict_types=1);
/**
 * Kooser PasswordLock - Secure your password using password lock.
 * 
 * @package Kooser\PasswordLock.
 */

namespace Kooser\PasswordLock\Exception;

use Exception;

/**
 * For invalid passwords.
 */
class PasswordInvalidException extends Exception implements ExceptionInterface
{
}
