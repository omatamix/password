[![Build Status](https://travis-ci.org/Kooser6/PasswordLock.svg?branch=master)](https://travis-ci.org/Kooser6/PasswordLock)
[![Coverage Status](https://coveralls.io/repos/github/Kooser6/PasswordLock/badge.svg?branch=master)](https://coveralls.io/github/Kooser6/PasswordLock?branch=master)

# PasswordLock

Secure your password using password lock.

## Installation

via Composer:

The best way to install this php component is through composer. If you do not have composer installed you can install it directly from the [composer website](https://getcomposer.org/). After composer is successfully install run the command line code below.

```sh
composer require kooser/password-lock
```

## Usage

### Basic Usage

It is very easy to use a hasher.

> When using the pbkdf2 hasher you must also provide the password on the `needsRehash` method.

```php
<?php declare(strict_types=1);

// Composer autoload.
require_once __DIR__ . '/vendor/autoload.php';

// Construct bcrypt hasher.
$bcrypt = new Kooser\PasswordLock\Bcrypt([
    'cost' => 10,
], false);

// Define our password.
$password = 'Kooser';

// Compute a new password.
$hash = $bcrypt->compute($password);

var_dump($hash);

// Check to see if the password matches the hash.
$verified = $bcrypt->verify($password, $hash);

var_dump($verified);

// Construct argon2i hasher
$argon2i = new Kooser\PasswordLock\Argon2i([], false);

// Check to see if the bcrypt hash needs to be rehashed to an argon2i hash.
$needsRehash = $argon2i->needsRehash($hash);

var_dump($needsRehash);
```

### Hash Info

Every hasher also comes with the `getInfo` method to get information on a hash.

## Contributing

All contributions are welcome! If you wish to contribute.

## License

This project is licensed under the terms of the [MIT License](https://opensource.org/licenses/MIT).
