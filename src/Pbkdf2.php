<?php declare(strict_types=1);

namespace Omatamix\PasswordLock;

use Symfony\Component\OptionsResolver\OptionsResolver;

/**
 * Hash the password using the pbkdf2 algorithm.
 */
final class Pbkdf2 extends AbstractLock implements LockInterface
{

    /** @var array $options The pbkdf2 hasher options. */
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
     */
    public function compute(string $password): string
    {
        return '$pbkdf2$' . \hash_pbkdf2($this->options['algo'], $password, $this->options['salt'], $this->options['iterations']);
    }

    /**
     * {@inheritdoc}
     *
     * @throws Exception\PasswordNotVerifiedException If exceptions enabled throw this exception
     *                                                if the password is not verified.
     */
    public function verify(string $password, string $hash): bool
    {
        
        if (\hash_equals($this->compute($password), $hash)) {
            return \true;
        } elseif ($this->exceptions) {
            throw new Exception\PasswordNotVerifiedException('The password supplied is not verified.');
        }
        return \false;
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
            'iterations' => 100000,
        ]);
        $resolver->setRequired('algo');
        $resolver->setRequired('salt');
        $resolver->setAllowedTypes('algo', 'string');
        $resolver->setAllowedTypes('salt', 'string');
        $resolver->setAllowedTypes('iterations', 'int');
    }
}
