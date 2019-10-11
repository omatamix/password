[![Build Status](https://travis-ci.org/kooser-framework/password-lock.svg?branch=master)](https://travis-ci.org/kooser-framework/password-lock)
[![Coverage Status](https://coveralls.io/repos/github/kooser-framework/password-lock/badge.svg?branch=master)](https://coveralls.io/github/kooser-framework/password-lock?branch=master)

# PasswordLock

Secure your password using password lock.

## Installation

via Composer:

The best way to install this php component is through composer. If you do not have composer installed you can install it directly from the [composer website](https://getcomposer.org/). After composer is successfully installed run the command line code below.

```sh
composer require kooser/password-lock
```

## Usage

### Basic usage

Using the hashers are very easy. Here is an example below.


```php
<?php

use Kooser\Framework\PasswordLock\Argon2id;

// Require the composer autoloader.
require_once __DIR__ . '/vendor/autoload.php';

// Define our argon2id hasher
$hasher = new Argon2id();

// Define our password.
$password = 'Hello World!';

// Compute a new hash.
$hash = $hasher->compute($password);
var_dump($hash);

// Verify the hash. 
var_dump($hasher->verify($password, $hash));

// Verify if the password needs a rehash.
var_dump($hasher->needsRehash($hash));

```

We have have other hashers like `Bcrypt`, `Argon2i`, and `Pbkdf2`.


## Contributing

All contributions are welcome! If you wish to contribute.

## License

This project is licensed under the terms of the [MIT License](https://opensource.org/licenses/MIT).
