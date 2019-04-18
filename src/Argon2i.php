
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
 * Hash the password using the argon2i algorithm.
 */
class Argon2i extends AbstractLock implements LockInterface
{

    /** @var array $options The bcrypt hasher options. */
    private $options = [];

    /** @var bool $exceptions Should we utilize exceptions. */
    protected $exceptions = \true;

    /**
     * Construct a new argon2i hasher.
     *
     * @param array $options    The argon2i hasher options.
     * @param bool  $exceptions Should we utilize exceptions.
     *
     * @return void Returns nothing.
     */
    public function __construct(array $options = [], bool $exceptions = \true)
    {
        $this->exceptions = $exceptions;
        $this->setOptions($options);
    }

    /**
     * Set the argon2i hasher options.
     *
     * @param array $options The argon2i hasher options.
     *
     * @return void Returns nothing.
     */
    public function setOptions(array $options = []): void
    {
        $resolver = new OptionsResolver();
        $this->configureOptions($resolver);
        $this->options = $resolver->resolve($options);
    }

    /**
     * Compute a new hash.
     *
     * @param string $password The password to hash.
     *
     * @return string Returns the password hashed.
     */
    public function compute(string $password): string
    {
        return \password_hash($password, \PASSWORD_ARGON2I, $this->options);
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
            return \password_verify($password, $hash);
        } elseif ($verified = \password_verify($password, $hash)) {
            return (bool) $verified;
        } else {
            throw new Exception\PasswordNotVerifiedException('The password supplied is not verified.');
        }
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
            if ($result = \is_pbkdf2($hash)) {
                return $result;
            }
            return \password_needs_rehash($hash, \PASSWORD_ARGON2I, $this->options);
        } elseif (\is_pbkdf2($hash)) {
            throw new Exception\PasswordNeedsRehashException('The hash supplied needs to be rehashed.');
        } elseif ($needsRehash = \password_needs_rehash($hash, \PASSWORD_ARGON2I, $this->options)) {
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
            'memory_cost' => \PASSWORD_ARGON2_DEFAULT_MEMORY_COST,
            'time_cost'   => \PASSWORD_ARGON2_DEFAULT_TIME_COST,
            'threads'     => \PASSWORD_ARGON2_DEFAULT_THREADS,
        ]);
    }
}
