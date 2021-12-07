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

use Omatamix\Password\Bcrypt;
use Omatamix\Password\Exception\PasswordInvalidException;
use PHPUnit\Framework\TestCase;

class BcryptTest extends TestCase
{
    /**
     * @return void Returns nothing.
     */
    public function testBcryptHash(): void
    {
        $options = ['cost' => 10];
        $bcrypt = new Bcrypt($options);
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
        $bcrypt = new Bcrypt($options);
        $hash = $bcrypt->compute('Hello World!');
        $this->assertTrue($bcrypt->verify('Hello World!', $hash));
    }

    /**
     * @return void Returns nothing.
     */
    public function testBcryptHashNeedsRehashAndExceptionOnTrueStatement(): void
    {
        $options = ['cost' => 10];
        $bcrypt = new Bcrypt($options);
        $hash = $bcrypt->compute('Hello World!');
        $this->assertTrue($bcrypt->verify('Hello World!', $hash));
        $this->assertTrue(!$bcrypt->verify('Hello Tom!', $hash));
        $options = ['cost' => 15];
        $bcrypt2 = new Bcrypt($options);
        $this->assertTrue($bcrypt2->needsRehash($hash));
        $options = ['cost' => 10];
        $bcrypt3 = new Bcrypt($options);
        $this->assertTrue(!$bcrypt3->needsRehash($hash));
    }

    /**
     * @return void Returns nothing.
     */
    public function testBcryptHashInvalidPasswordException(): void
    {
        $this->expectException(PasswordInvalidException::class);
        $options = ['cost' => 10];
        $bcrypt = new Bcrypt($options);
        $hash = $bcrypt->compute('WWEPt2AEjqqM?DeSV&SXcU=t*^D5Bte#E*R8c3-_kq!bBU$ahjgJFL+Q=2gG?#QqkwzS?qwbs');
    }
}
