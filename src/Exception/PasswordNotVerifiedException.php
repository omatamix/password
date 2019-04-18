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
 * For the verify hash function.
 */
class PasswordNotVerifiedException extends Exception implements ExceptionInterface
{
}
