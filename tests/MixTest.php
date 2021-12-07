<?php
declare(strict_types=1);
/**
 * Omatamix Password
 *
 * MIT License
 * 
 * Copyright (c) 2022 Nicholas English
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

namespace Omatamix\Password\Test;

use Omatamix\Password\Argon2i;
use Omatamix\Password\Argon2id;
use Omatamix\Password\Bcrypt;
use Omatamix\Password\Pbkdf2;
use PHPUnit\Framework\TestCase;

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
        ]);
        $argon2i = new Argon2i([]);
        $argon2id = new Argon2id([]);
        $hash = $pbkdf2->compute('KooserPHP!');
        $this->assertTrue($bcrypt->needsRehash($hash));
        $this->assertTrue($argon2i->needsRehash($hash));
        $this->assertTrue($argon2id->needsRehash($hash));
    }
}
