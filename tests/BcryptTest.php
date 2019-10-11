<?php
declare(strict_types=1);
/**
 * Kooser PasswordLock - Secure your password using password lock.
 * 
 * @package Kooser\PasswordLock.
 */

namespace PasswordLock\Test;

use Kooser\Framework\PasswordLock\Bcrypt;
use Kooser\Framework\PasswordLock\Exception\PasswordInvalidException;
use Kooser\Framework\PasswordLock\Exception\PasswordNeedsRehashException;
use Kooser\Framework\PasswordLock\Exception\PasswordNotVerifiedException;

use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Error\Error;

/**
 * Test bcrypt functionality.
 */
class BcryptTest extends TestCase
{

    /**
     * @return void Returns nothing.
     */
    public function testBcryptHash(): void
    {
        $options = ['cost' => 10];
        $bcrypt = new Bcrypt($options, \false);
        $hash = $bcrypt->compute('Hello World!');
        $this->assertTrue($bcrypt->verify('Hello World!', $hash));
        $this->assertTrue(!$bcrypt->verify('Hello Tom!', $hash));
    }

    /**
     * @return void Returns nothing.
     */
    public function testBcryptHashAgainstExceptionsOnTrue(): void
    {
        $options = ['cost' => 10];
        $bcrypt = new Bcrypt($options, \true);
        $hash = $bcrypt->compute('Hello World!');
        $this->assertTrue($bcrypt->verify('Hello World!', $hash));
    }

    /**
     * @return void Returns nothing.
     */
    public function testBcryptHashAgainstExceptionsOnPasswordNeedsRehash(): void
    {
        $this->expectException(PasswordNeedsRehashException::class);
        $options = ['cost' => 10];
        $bcrypt = new Bcrypt($options, \true);
        $hash = $bcrypt->compute('Hello World!');
        $options = ['cost' => 15];
        $bcrypt = new Bcrypt($options, \true);
        $bcrypt->needsRehash($hash);
    }

    /**
     * @return void Returns nothing.
     */
    public function testBcryptHashAgainstExceptionsOnPasswordVerify(): void
    {
        $this->expectException(PasswordNotVerifiedException::class);
        $options = ['cost' => 10];
        $bcrypt = new Bcrypt($options, \true);
        $hash = $bcrypt->compute('Hello World!');
        $res = $bcrypt->verify('Hello Tom!', $hash);
    }

    /**
     * @return void Returns nothing.
     */
    public function testBcryptHashNeedsRehashAndExceptionOnTrueStatement(): void
    {
        $options = ['cost' => 10];
        $bcrypt = new Bcrypt($options, \false);
        $hash = $bcrypt->compute('Hello World!');
        $this->assertTrue($bcrypt->verify('Hello World!', $hash));
        $this->assertTrue(!$bcrypt->verify('Hello Tom!', $hash));
        $options = ['cost' => 15];
        $bcrypt2 = new Bcrypt($options, \false);
        $this->assertTrue($bcrypt2->needsRehash($hash));
        $options = ['cost' => 10];
        $bcrypt3 = new Bcrypt($options, \true);
        $this->assertTrue(!$bcrypt3->needsRehash($hash));
    }

    /**
     * @return void Returns nothing.
     */
    public function testBcryptHashInvalidPasswordException(): void
    {
        $this->expectException(PasswordInvalidException::class);
        $options = ['cost' => 10];
        $bcrypt = new Bcrypt($options, \true);
        $hash = $bcrypt->compute('WWEPt2AEjqqM?DeSV&SXcU=t*^D5Bte#E*R8c3-_kq!bBU$ahjgJFL+Q=2gG?#QqkwzS?qwbs');
    }

    /**
     * @return void Returns nothing.
     */
    public function testBcryptHashInvalidPasswordError(): void
    {
        $this->expectException(Error::class);
        $options = ['cost' => 10];
        $bcrypt = new Bcrypt($options, \false);
        $hash = $bcrypt->compute('WWEPt2AEjqqM?DeSV&SXcU=t*^D5Bte#E*R8c3-_kq!bBU$ahjgJFL+Q=2gG?#QqkwzS?qwbs');
    }
}
