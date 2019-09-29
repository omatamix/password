<?php
declare(strict_types=1);
/**
 * Kooser PasswordLock - Secure your password using password lock.
 * 
 * @package Kooser\PasswordLock.
 */

namespace Kooser\PasswordLock;

use Symfony\Component\OptionsResolver\OptionsResolver;

/**
 * Hash the password using the pbkdf2 algorithm.
 */
final class Pbkdf2 extends AbstractLock implements LockInterface
{

    /** @var array $options The pbkdf2 hasher options. */
    private $options = [];

    /** @var bool $exceptions Should we utilize exceptions. */
    private $exceptions = \true;

    /**
     * Construct a new pbkdf2 hasher.
     *
     * @param array $options    The pbkdf2 hasher options.
     * @param bool  $exceptions Should we utilize exceptions.
     *
     * @return void Returns nothing.
     */
    public function __construct(array $options = [], bool $exceptions = \true)
    {
        $this->setExceptions($exceptions);
        $this->setOptions($options);
    }

    /**
     * Set the pbkdf2 hasher options.
     *
     * @param array $options The pbkdf2 hasher options.
     *
     * @return \Kooser\PasswordLock\LockInterface Returns the hasher.
     */
    public function setOptions(array $options = []): LockInterface
    {
        $resolver = new OptionsResolver();
        $this->configureOptions($resolver);
        $this->options = $resolver->resolve($options);
        return $this;
    }

    /**
     * Set the exceptions param.
     *
     * @param bool $exceptions Should we utilize exceptions.
     *
     * @return \Kooser\PasswordLock\LockInterface Returns the hasher.
     */
    public function setExceptions(bool $exceptions = \true): LockInterface
    {
        $this->exceptions = $exceptions;
        return $this;
    }

    /**
     * Compute a new hash.
     *
     * @param string $password The password to hash.
     *
     * @throws Exception\PasswordInvalidException If the password supplied is invalid.
     *
     * @return string Returns the password hashed.
     */
    public function compute(string $password): string
    {
        return '$pbkdf2$' . \hash_pbkdf2($this->options['algo'], $password, $this->options['salt'], $this->options['iterations']);
    }
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
    public function verify(string $password, string $hash): bool
    {
        if (!$this->exceptions) {
            return \hash_equals($this->compute($password), $hash);
        } elseif ($verified = \hash_equals($this->compute($password), $hash)) {
            return (bool) $verified;
        } else {
            throw new Exception\PasswordNotVerifiedException('The password supplied is not verified.');
        }
    }

    /**
     * Determine if the hash needs a rehash.
     *
     * @param string $password The password for the hash.
     * @param string $hash     The hash to check.
     *
     * @throws Exception\PasswordNeedsRehashException If exceptions enabled throw this exception
     *                                                if the hash needs a rehash.
     *
     * @return bool Returns true if the hash needs a rehash and false if not.
     */
    public function needsRehash(string $password, string $hash): bool
    {
        $testHash = $this->compute($password);
        $res = \hash_equals($testHash, $hash);
        if (!$this->exceptions) {
            return !(\is_pbkdf2($hash) && $res);
        } elseif ($needsRehash = !(\is_pbkdf2($hash) && $res)) {
            throw new Exception\PasswordNeedsRehashException('The hash supplied needs to be rehashed.');
        } else {
            return (bool) $needsRehash;
        }
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
            'iterations' => 100000,
        ]);
        $resolver->setRequired('algo');
        $resolver->setRequired('salt');
        $resolver->setAllowedTypes('algo', 'string');
        $resolver->setAllowedTypes('salt', 'string');
        $resolver->setAllowedTypes('iterations', 'int');
    }
}
