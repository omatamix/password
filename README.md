[![Travis (.org) branch](https://img.shields.io/travis/Kooser6/PasswordLock/master.svg?style=flat-square)](https://travis-ci.org/Kooser6/PasswordLock)
[![Coveralls github branch](https://img.shields.io/coveralls/github/Kooser6/PasswordLock/master.svg?style=flat-square)](https://coveralls.io/github/Kooser6/PasswordLock?branch=master)

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

use Kooser\PasswordLock\Argon2id;

// Require the composer autoloader.
require_once __DIR__ . '/vendor/autoload.php';

// Define our argon2i hasher
// Avaliable hashers:
// `Argon2i`, `Argon2id`, `Bcrypt`, and `Pbkdf2`.
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

## Contributing

All contributions are welcome! If you wish to contribute.

## License

This project is licensed under the terms of the [MIT License](https://opensource.org/licenses/MIT).
