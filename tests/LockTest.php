<?php
declare(strict_types=1);
/**
 * Kooser PasswordLock - Secure your password using password lock.
 * 
 * @package Kooser\PasswordLock.
 */

namespace PasswordLock\Test;

use Kooser\PasswordLock\Bcrypt;
use Kooser\PasswordLock\Pbkdf2;

use PHPUnit\Framework\TestCase;

/**
 * Test the lock abstraction.
 */
class LockTest extends TestCase
{

    /**
     * @return void Returns nothing.
     */
    public function testHashInfoBcryptPbkdf2(): void
    {
        $bcrypt = new Bcrypt();
        $pbkdf2 = new Pbkdf2([
            'algo' => 'sha512',
            'salt' => 'Kooser',
        ]);
        $hash1 = $bcrypt->compute('KooserPHP!');
        $hash2 = $pbkdf2->compute('KooserPHP!');
        $this->assertTrue(\is_array($bcrypt->getInfo($hash1)));
        $info = $pbkdf2->getInfo($hash2);
        $this->assertTrue(\is_array($info));
    }
}
