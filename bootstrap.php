<?php declare(strict_types=1);

defined('PASSWORD_PBKDF2') || define('PASSWORD_PBKDF2', 5506);

/**
 * Determine if the hash is pbkdf2.
 *
 * @param string $hash The hash to check.
 *
 * @return bool Returns true if the hash is pbkdf2 and false if not.
 */
function is_pbkdf2(string $hash): bool
{
    $component = substr($hash, 0, 8);
    return (bool) ($component == '$pbkdf2$');
}
