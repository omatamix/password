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

use Omatamix\Password\Argon2id;
use PHPUnit\Framework\TestCase;

class Argon2idTest extends TestCase
{
    /**
     * @return void Returns nothing.
     */
    public function testArgon2idHash(): void
    {
        $options = [
            'memory_cost' => PASSWORD_ARGON2_DEFAULT_MEMORY_COST,
            'time_cost'   => PASSWORD_ARGON2_DEFAULT_TIME_COST,
            'threads'     => PASSWORD_ARGON2_DEFAULT_THREADS,
        ];
        $argon2id = new Argon2id($options);
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
            'memory_cost' => PASSWORD_ARGON2_DEFAULT_MEMORY_COST,
            'time_cost'   => PASSWORD_ARGON2_DEFAULT_TIME_COST,
            'threads'     => PASSWORD_ARGON2_DEFAULT_THREADS,
        ];
        $argon2id = new Argon2id($options);
        $hash = $argon2id->compute('Hello World!');
        $this->assertTrue($argon2id->verify('Hello World!', $hash));
    }

    /**
     * @return void Returns nothing.
     */
    public function testArgon2idHashNeedsRehashAndExceptionOnTrueStatement(): void
    {
        $options = [
            'memory_cost' => PASSWORD_ARGON2_DEFAULT_MEMORY_COST,
            'time_cost'   => PASSWORD_ARGON2_DEFAULT_TIME_COST,
            'threads'     => PASSWORD_ARGON2_DEFAULT_THREADS,
        ];
        $argon2id = new Argon2id($options);
        $hash = $argon2id->compute('Hello World!');
        $this->assertTrue($argon2id->verify('Hello World!', $hash));
        $this->assertTrue(!$argon2id->verify('Hello Tom!', $hash));
        $options = [
            'memory_cost' => 6,
        ];
        $argon2id2 = new Argon2id($options);
        $this->assertTrue($argon2id2->needsRehash($hash));
        $options = [
            'memory_cost' => PASSWORD_ARGON2_DEFAULT_MEMORY_COST,
            'time_cost'   => PASSWORD_ARGON2_DEFAULT_TIME_COST,
            'threads'     => PASSWORD_ARGON2_DEFAULT_THREADS,
        ];
        $argon2id3 = new Argon2id($options);
        $this->assertTrue(!$argon2id3->needsRehash($hash));
    }
}
