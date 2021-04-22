<?php declare(strict_types=1);

namespace Omatamix\PasswordLock;

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
    public function __construct(array $options = []);

    /**
     * Set the hasher options.
     *
     * @param array $options The hasher options.
     *
     * @return \PasswordLock\LockInterface Returns the hasher.
     */
    public function setOptions(array $options = []): LockInterface;

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
     * @return bool Returns true if the password is verified and false if not.
     */
    public function verify(string $password, string $hash): bool;
}
