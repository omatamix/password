<?php declare(strict_types=1);

namespace Omatamix\PasswordLock;

/**
 * The abstract hasher.
 */
abstract class AbstractLock
{
    /**
     * Get informtion on a hash.
     *
     * @param string $hash The hash to get info on.
     *
     * @return array Info on the hash.
     */
    public function getInfo(string $hash): array
    {
        if (is_pbkdf2($hash)) {
            return [
                'algo'     => PASSWORD_PBKDF2,
                'algoName' => 'pbkdf2',
                'options'  => null,
            ];
        }
        $info = password_get_info($hash);
        $info['options'] = null;
        return $info;
    }
}
