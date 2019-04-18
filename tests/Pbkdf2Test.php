<?php
declare(strict_types=1);
/**
 * PasswordLock - Secure your password using password lock.
 *
 * @author Nicholas English <https://github.com/bonvil>.
 * @license A short and simple permissive license with conditions only requiring preservation of copyright and license notices.
 *          Licensed works, modifications, and larger works may be distributed under different terms and without source code.
 *
 * @link <https://github.com/razephp/password-lock/blob/master/LICENSE> MIT License.
 * @link <https://github.com/razephp/password-lock> Source.
 */
namespace PasswordLock\Test;
use PasswordLock\Exception\PasswordNeedsRehash;
use PasswordLock\Exception\PasswordNotVerified;
use PasswordLock\Pbkdf2;
use PHPUnit\Framework\TestCase;
use const false;
use const true;
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
            'salt' => 'Kooser'
        ], \true);
        $hash = $pbkdf2->compute('Hello World!');
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
