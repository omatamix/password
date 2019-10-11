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
 * For the verify hash function.
 */
class PasswordNotVerifiedException extends Exception implements ExceptionInterface
{
}
