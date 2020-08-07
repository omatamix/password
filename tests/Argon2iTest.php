<?php declare(strict_types=1);

namespace Omatamix\PasswordLock\Test;

use Omatamix\PasswordLock\Argon2i;
use Omatamix\PasswordLock\Exception\PasswordNeedsRehashException;
use Omatamix\PasswordLock\Exception\PasswordNotVerifiedException;

use PHPUnit\Framework\TestCase;

/**
 * Test argon2i functionality.
 */
class Argon2iTest extends TestCase
{

    /**
     * @return void Returns nothing.
     */
    public function testArgon2iHash(): void
    {
        $options = [
            'memory_cost' => \PASSWORD_ARGON2_DEFAULT_MEMORY_COST,
            'time_cost'   => \PASSWORD_ARGON2_DEFAULT_TIME_COST,
            'threads'     => \PASSWORD_ARGON2_DEFAULT_THREADS,
        ];
        $argon2i = new Argon2i($options, \false);
        $hash = $argon2i->compute('Hello World!');
        $this->assertTrue($argon2i->verify('Hello World!', $hash));
        $this->assertTrue(!$argon2i->verify('Hello Tom!', $hash));
    }

    /**
     * @return void Returns nothing.
     */
    public function testArgon2iHashAgainstExceptionsOnTrue(): void
    {
        $options = [
            'memory_cost' => \PASSWORD_ARGON2_DEFAULT_MEMORY_COST,
            'time_cost'   => \PASSWORD_ARGON2_DEFAULT_TIME_COST,
            'threads'     => \PASSWORD_ARGON2_DEFAULT_THREADS,
        ];
        $argon2i = new Argon2i($options, \true);
        $hash = $argon2i->compute('Hello World!');
        $this->assertTrue($argon2i->verify('Hello World!', $hash));
    }

    /**
     * @return void Returns nothing.
     */
    public function testArgon2iHashAgainstExceptionsOnPasswordNeedsRehash(): void
    {
        $this->expectException(PasswordNeedsRehashException::class);
        $options = [
            'memory_cost' => \PASSWORD_ARGON2_DEFAULT_MEMORY_COST,
            'time_cost'   => \PASSWORD_ARGON2_DEFAULT_TIME_COST,
            'threads'     => \PASSWORD_ARGON2_DEFAULT_THREADS,
        ];
        $argon2i = new Argon2i($options, \true);
        $hash = $argon2i->compute('Hello World!');
        $options = ['memory_cost' => 6];
        $argon2i = new Argon2i($options, \true);
        $argon2i->needsRehash($hash);
    }

    /**
     * @return void Returns nothing.
     */
    public function testArgon2iHashAgainstExceptionsOnPasswordVerify(): void
    {
        $this->expectException(PasswordNotVerifiedException::class);
        $options = [
            'memory_cost' => \PASSWORD_ARGON2_DEFAULT_MEMORY_COST,
            'time_cost'   => \PASSWORD_ARGON2_DEFAULT_TIME_COST,
            'threads'     => \PASSWORD_ARGON2_DEFAULT_THREADS,
        ];
        $argon2i = new Argon2i($options, \true);
        $hash = $argon2i->compute('Hello World!');
        $res = $argon2i->verify('Hello Tom!', $hash);
    }

    /**
     * @return void Returns nothing.
     */
    public function testArgon2iHashNeedsRehashAndExceptionOnTrueStatement(): void
    {
        $options = [
            'memory_cost' => \PASSWORD_ARGON2_DEFAULT_MEMORY_COST,
            'time_cost'   => \PASSWORD_ARGON2_DEFAULT_TIME_COST,
            'threads'     => \PASSWORD_ARGON2_DEFAULT_THREADS,
        ];
        $argon2i = new Argon2i($options, \false);
        $hash = $argon2i->compute('Hello World!');
        $this->assertTrue($argon2i->verify('Hello World!', $hash));
        $this->assertTrue(!$argon2i->verify('Hello Tom!', $hash));
        $options = [
            'memory_cost' => 6,
        ];
        $argon2i2 = new Argon2i($options, \false);
        $this->assertTrue($argon2i2->needsRehash($hash));
        $options = [
            'memory_cost' => \PASSWORD_ARGON2_DEFAULT_MEMORY_COST,
            'time_cost'   => \PASSWORD_ARGON2_DEFAULT_TIME_COST,
            'threads'     => \PASSWORD_ARGON2_DEFAULT_THREADS,
        ];
        $argon2i3 = new Argon2i($options, \true);
        $this->assertTrue(!$argon2i3->needsRehash($hash));
    }
}
