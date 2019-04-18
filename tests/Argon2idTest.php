    
<?php
declare(strict_types=1);
/**
 * Kooser PasswordLock - Secure your password using password lock.
 * 
 * @package Kooser\PasswordLock.
 */

namespace PasswordLock\Test;

use Kooser\PasswordLock\Argon2id;
use Kooser\PasswordLock\Exception\PasswordNeedsRehashException;
use Kooser\PasswordLock\Exception\PasswordNotVerifiedException;

use PHPUnit\Framework\TestCase;

/**
 * Test argon2id functionality.
 */
class Argon2idTest extends TestCase
{

    /**
     * @return void Returns nothing.
     */
    public function testArgon2idHash(): void
    {
        $options = [
            'memory_cost' => \PASSWORD_ARGON2_DEFAULT_MEMORY_COST,
            'time_cost'   => \PASSWORD_ARGON2_DEFAULT_TIME_COST,
            'threads'     => \PASSWORD_ARGON2_DEFAULT_THREADS,
        ];
        $argon2id = new Argon2id($options, \false);
        $hash = $argon2id->compute('Hello World!');
        $this->assertTrue($argon2id->verify('Hello World!', $hash));
        $this->assertTrue(!$argon2id->verify('Hello Tom!', $hash));
    }

    /**
     * @return void Returns nothing.
     */
    public function testArgon2idHashAgainstExceptionsOnTrue(): void
    {
        $options = [
            'memory_cost' => \PASSWORD_ARGON2_DEFAULT_MEMORY_COST,
            'time_cost'   => \PASSWORD_ARGON2_DEFAULT_TIME_COST,
            'threads'     => \PASSWORD_ARGON2_DEFAULT_THREADS,
        ];
        $argon2id = new Argon2id($options, \true);
        $hash = $argon2id->compute('Hello World!');
        $this->assertTrue($argon2id->verify('Hello World!', $hash));
    }

    /**
     * @return void Returns nothing.
     */
    public function testArgon2idHashAgainstExceptionsOnPasswordNeedsRehash(): void
    {
        $this->expectException(PasswordNeedsRehashException::class);
        $options = [
            'memory_cost' => \PASSWORD_ARGON2_DEFAULT_MEMORY_COST,
            'time_cost'   => \PASSWORD_ARGON2_DEFAULT_TIME_COST,
            'threads'     => \PASSWORD_ARGON2_DEFAULT_THREADS,
        ];
        $argon2id = new Argon2id($options, \true);
        $hash = $argon2id->compute('Hello World!');
        $options = ['memory_cost' => 6];
        $argon2id = new Argon2id($options, \true);
        $argon2id->needsRehash($hash);
    }

    /**
     * @return void Returns nothing.
     */
    public function testArgon2idHashAgainstExceptionsOnPasswordVerify(): void
    {
        $this->expectException(PasswordNotVerifiedException::class);
        $options = [
            'memory_cost' => \PASSWORD_ARGON2_DEFAULT_MEMORY_COST,
            'time_cost'   => \PASSWORD_ARGON2_DEFAULT_TIME_COST,
            'threads'     => \PASSWORD_ARGON2_DEFAULT_THREADS,
        ];
        $argon2id = new Argon2id($options, \true);
        $hash = $argon2id->compute('Hello World!');
        $res = $argon2id->verify('Hello Tom!', $hash);
    }

    /**
     * @return void Returns nothing.
     */
    public function testArgon2idHashNeedsRehashAndExceptionOnTrueStatement(): void
    {
        $options = [
            'memory_cost' => \PASSWORD_ARGON2_DEFAULT_MEMORY_COST,
            'time_cost'   => \PASSWORD_ARGON2_DEFAULT_TIME_COST,
            'threads'     => \PASSWORD_ARGON2_DEFAULT_THREADS,
        ];
        $argon2id = new Argon2id($options, \false);
        $hash = $argon2id->compute('Hello World!');
        $this->assertTrue($argon2id->verify('Hello World!', $hash));
        $this->assertTrue(!$argon2id->verify('Hello Tom!', $hash));
        $options = [
            'memory_cost' => 6,
        ];
        $argon2id2 = new Argon2id($options, \false);
        $this->assertTrue($argon2id2->needsRehash($hash));
        $options = [
            'memory_cost' => PASSWORD_ARGON2_DEFAULT_MEMORY_COST,
            'time_cost'   => PASSWORD_ARGON2_DEFAULT_TIME_COST,
            'threads'     => PASSWORD_ARGON2_DEFAULT_THREADS,
        ];
        $argon2id3 = new Argon2id($options, \true);
        $this->assertTrue(!$argon2id3->needsRehash($hash));
    }
}
