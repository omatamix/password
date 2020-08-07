<?php declare(strict_types=1);

namespace Omatamix\PasswordLock\Test;

use Omatamix\PasswordLock\Argon2i;
use Omatamix\PasswordLock\Argon2id;
use Omatamix\PasswordLock\Bcrypt;
use Omatamix\PasswordLock\Exception\PasswordNeedsRehashException;
use Omatamix\PasswordLock\Pbkdf2;

use PHPUnit\Framework\TestCase;

/**
 * Test mix functionality.
 */
class MixTest extends TestCase
{
    /**
     * @return void Returns nothing.
     */
    public function testMix(): void
    {
        $pbkdf2 = new Pbkdf2([
            'algo' => 'sha512',
            'salt' => 'Kooser'
        ]);
        $bcrypt = new Bcrypt([
            'cost' => 10,
        ], \false);
        $argon2i = new Argon2i([], \false);
        $argon2id = new Argon2id([], \false);
        $hash = $pbkdf2->compute('KooserPHP!');
        $this->assertTrue($bcrypt->needsRehash($hash));
        $this->assertTrue($argon2i->needsRehash($hash));
        $this->assertTrue($argon2id->needsRehash($hash));
    }

    /**
     * @return void Returns nothing.
     */
    public function testMixArgon2i(): void
    {
        $this->expectException(PasswordNeedsRehashException::class);
        $pbkdf2 = new Pbkdf2([
            'algo' => 'sha512',
            'salt' => 'Kooser'
        ]);
        $argon2i = new Argon2i();
        $hash = $pbkdf2->compute('KooserPHP!');
        $argon2i->needsRehash($hash);
    }

    /**
     * @return void Returns nothing.
     */
    public function testMixArgon2id(): void
    {
        $this->expectException(PasswordNeedsRehashException::class);
        $pbkdf2 = new Pbkdf2([
            'algo' => 'sha512',
            'salt' => 'Kooser'
        ]);
        $argon2id = new Argon2id();
        $hash = $pbkdf2->compute('KooserPHP!');
        $argon2id->needsRehash($hash);
    }

    /**
     * @return void Returns nothing.
     */
    public function testMixBcrypt(): void
    {
        $this->expectException(PasswordNeedsRehashException::class);
        $pbkdf2 = new Pbkdf2([
            'algo' => 'sha512',
            'salt' => 'Kooser'
        ]);
        $bcrypt = new Bcrypt(['cost' => 10]);
        $hash = $pbkdf2->compute('KooserPHP!');
        $bcrypt->needsRehash($hash);
    }
}
