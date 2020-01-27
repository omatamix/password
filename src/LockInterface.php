<?php declare(strict_types=1);
/**
 * PasswordLock - Secure your password using password lock.
 *
 * @license MIT License. (https://github.com/Commander-Ant-Screwbin-Games/password-lock/blob/master/license)
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
 * https://github.com/Commander-Ant-Screwbin-Games/firecms/tree/master/src/Core
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * @package Commander-Ant-Screwbin-Games/password-lock.
 */

namespace PasswordLock;

/**
 * The hasher interface.
 */
interface LockInterface
{

    /**
     * Construct a new hasher.
     *
     * @param array $options    The hasher options.
     * @param bool  $exceptions Should we utilize exceptions.
     *
     * @return void Returns nothing.
     */
    public function __construct(array $options = [], bool $exceptions = \true);

    /**
     * Set the hasher options.
     *
     * @param array $options The hasher options.
     *
     * @return \PasswordLock\LockInterface Returns the hasher.
     */
    public function setOptions(array $options = []): LockInterface;

    /**
     * Set the exceptions param.
     *
     * @param bool $exceptions Should we utilize exceptions.
     *
     * @return \PasswordLock\LockInterface Returns the hasher.
     */
    public function setExceptions(bool $exceptions = \true): LockInterface;

    /**
     * Compute a new hash.
     *
     * @param string $password The password to hash.
     *
     * @return string Returns the password hashed.
     */
    public function compute(string $password): string;

    /**
     * Verify the password matches the given hash.
     *
     * @param string $password The password to verify.
     * @param string $hash     The hash to verify against.
     *
     * @throws Exception\PasswordNotVerifiedException If exceptions enabled throw this exception
     *                                                if the password is not verified.
     *
     * @return bool Returns true if the password is verified and false if not.
     */
    public function verify(string $password, string $hash): bool;
}
