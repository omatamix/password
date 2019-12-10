<?php
declare(strict_types=1);

namespace PasswordLock\Test;

use PasswordLock\Pbkdf2;
use PasswordLock\Exception\PasswordNeedsRehashException;
use PasswordLock\Exception\PasswordNotVerifiedException;

use PHPUnit\Framework\TestCase;

/**
 * Test pbkdf2 functionality.
 */
class Pbkdf2Test extends TestCase
{

    /**
     * @return void Returns nothing.
     */
    public function testPbkdf2Hash(): void
    {
        $pbkdf2 = new Pbkdf2([
            'algo' => 'sha512',
            'salt' => 'Kooser'
        ], \false);
        $hash = $pbkdf2->compute('Hello World!');
        $this->assertTrue($pbkdf2->verify('Hello World!', $hash));
        $this->assertTrue(!$pbkdf2->verify('Hello Tom!', $hash));
    }

    /**
     * @return void Returns nothing.
     */
    public function testPbkdf2HashAgainstExceptionsOnTrue(): void
    {
        $pbkdf2 = new Pbkdf2([
            'algo' => 'sha512',
            'salt' => 'Kooser'
        ], \true);
        $hash = $pbkdf2->compute('Hello World!');
        $this->assertTrue($pbkdf2->verify('Hello World!', $hash));
    }

    /**
     * @return void Returns nothing.
     */
    public function testPbkdf2HashAgainstExceptionsOnPasswordNeedsRehash(): void
    {
        $this->expectException(PasswordNeedsRehashException::class);
        $pbkdf2 = new Pbkdf2([
            'algo' => 'sha512',
            'salt' => 'KooserA'
        ], \true);
        $hash = $pbkdf2->compute('Hello World!');
        $pbkdf2 = new Pbkdf2([
            'algo' => 'sha512',
            'salt' => 'KooserB'
        ], \true);
        $pbkdf2->needsRehash('Hello World!', $hash);
    }

    /**
     * @return void Returns nothing.
     */
    public function testPbkdf2HashAgainstExceptionsOnPasswordVerify(): void
    {
        $this->expectException(PasswordNotVerifiedException::class);
        $pbkdf2 = new Pbkdf2([
            'algo' => 'sha512',
            'salt' => 'Kooser'
        ], \true);
        $hash = $pbkdf2->compute('Hello World!');
        $res = $pbkdf2->verify('Hello Tom!', $hash);
    }

    /**
     * @return void Returns nothing.
     */
    public function testPbkdf2HashNeedsRehashAndExceptionOnTrueStatement(): void
    {
        $options = ['algo' => 'sha512', 'salt' => 'KooserA'];
        $pbkdf2 = new Pbkdf2($options, \false);
        $hash = $pbkdf2->compute('Hello World!');
        $this->assertTrue($pbkdf2->verify('Hello World!', $hash));
        $this->assertTrue(!$pbkdf2->verify('Hello Tom!', $hash));
        $options = ['algo' => 'sha512', 'salt' => 'KooserB'];
        $pbkdf22 = new Pbkdf2($options, \false);
        $this->assertTrue($pbkdf22->needsRehash('Hello World!', $hash));
        $options = ['algo' => 'sha512', 'salt' => 'KooserA'];
        $pbkdf23 = new Pbkdf2($options, \true);
        $this->assertTrue(!$pbkdf23->needsRehash('Hello World!', $hash));
    }
}
