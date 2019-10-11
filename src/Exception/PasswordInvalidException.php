<?php
declare(strict_types=1);
/**
 * Kooser PasswordLock - Secure your password using password lock.
 * 
 * @package Kooser\Framework\PasswordLock.
 */

namespace Kooser\Framework\PasswordLock\Exception;

use Exception;

/**
 * For invalid passwords.
 */
class PasswordInvalidException extends Exception implements ExceptionInterface
{
}
