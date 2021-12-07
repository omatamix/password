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

use Omatamix\Password\Pbkdf2;
use PHPUnit\Framework\TestCase;

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
        ]);
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
        ]);
        $hash = $pbkdf2->compute('Hello World!');
        $this->assertTrue($pbkdf2->verify('Hello World!', $hash));
    }

    /**
     * @return void Returns nothing.
     */
    public function testPbkdf2HashNeedsRehashAndExceptionOnTrueStatement(): void
    {
        $options = ['algo' => 'sha512', 'salt' => 'KooserA'];
        $pbkdf2 = new Pbkdf2($options);
        $hash = $pbkdf2->compute('Hello World!');
        $this->assertTrue($pbkdf2->verify('Hello World!', $hash));
        $this->assertTrue(!$pbkdf2->verify('Hello Tom!', $hash));
        $options = ['algo' => 'sha512', 'salt' => 'KooserB'];
        $pbkdf22 = new Pbkdf2($options);
        $this->assertTrue($pbkdf22->needsRehash('Hello World!', $hash));
        $options = ['algo' => 'sha512', 'salt' => 'KooserA'];
        $pbkdf23 = new Pbkdf2($options);
        $this->assertTrue(!$pbkdf23->needsRehash('Hello World!', $hash));
    }
}
