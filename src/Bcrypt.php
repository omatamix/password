<?php declare(strict_types=1);
/**
 * MIT License
 * 
 * Copyright (c) 2021 Nicholas English
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

namespace Omatamix\PasswordLock;

use Symfony\Component\OptionsResolver\OptionsResolver;

/**
 * Hash the password using the crypt blowfish algorithm.
 */
final class Bcrypt extends AbstractLock implements LockInterface
{
    /** @var array $options The crypt blowfish hasher options. */
    private $options = [];

    /** @var bool $exceptions Should we utilize exceptions. */
    protected $exceptions = \true;

    /**
     * {@inheritdoc}
     */
    public function __construct(array $options = [], bool $exceptions = \true)
    {
        $this->setExceptions($exceptions);
        $this->setOptions($options);
    }

    /**
     * {@inheritdoc}
     */
    public function setOptions(array $options = []): LockInterface
    {
        $resolver = new OptionsResolver();
        $this->configureOptions($resolver);
        $this->options = $resolver->resolve($options);
        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function setExceptions(bool $exceptions = \true): LockInterface
    {
        $this->exceptions = $exceptions;
        return $this;
    }

    /**
     * {@inheritdoc}
     *
     * @throws Exception\PasswordInvalidException If the password supplied is invalid.
     */
    public function compute(string $password): string
    {
        if (!$this->exceptions && \mb_strlen($password) > 72) {
            \trigger_error('The password supplied is invalid. The max length for a password using bcrypt is 72.', E_USER_ERROR);
        } elseif (\mb_strlen($password) > 72) {
            throw new Exception\PasswordInvalidException('The password supplied is invalid. The max length for a password using bcrypt is 72.');
        }
        return \password_hash($password, \PASSWORD_BCRYPT, $this->options);
    }

    /**
     * {@inheritdoc}
     *
     * @throws Exception\PasswordNotVerifiedException If exceptions enabled throw this exception
     *                                                if the password is not verified.
     */
    public function verify(string $password, string $hash): bool
    {
        if (!$this->exceptions) {
            return \password_verify($password, $hash);
        } elseif (\password_verify($password, $hash)) {
            return \true;
        }
        throw new Exception\PasswordNotVerifiedException('The password supplied is not verified.');
    }

    /**
     * Determine if the hash needs a rehash.
     *
     * @param string $hash The hash to check.
     *
     * @throws Exception\PasswordNeedsRehashException If exceptions enabled throw this exception
     *                                                if the hash needs a rehash.
     *
     * @return bool Returns true if the hash needs a rehash and false if not.
     */
    public function needsRehash(string $hash): bool
    {
        if (!$this->exceptions) {
            return \is_pbkdf2($hash) ? \true : \password_needs_rehash($hash, \PASSWORD_BCRYPT, $this->options);
        } elseif (\is_pbkdf2($hash) || \password_needs_rehash($hash, \PASSWORD_BCRYPT, $this->options)) {
            throw new Exception\PasswordNeedsRehashException('The hash supplied needs to be rehashed.');
        }
        return \false;
    }

    /**
     * Configure the hasher options.
     *
     * @param OptionsResolver The symfony options resolver.
     *
     * @return void Returns nothing.
     */
    private function configureOptions(OptionsResolver $resolver): void
    {
        $resolver->setDefaults([
            'cost' => 10,
        ]);
        $resolver->setAllowedTypes('cost', 'int');
    }
}
