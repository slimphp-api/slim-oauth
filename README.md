# Slim Framework OAuth Middleware

This repository contains a Slim Framework OAuth middleware.

Enables you to authenticate using various OAuth providers.

## Install

Via Composer

``` bash
$ composer require slim/oauth
```

Requires Slim 3.0.0 or newer.

## Usage

```php

use Slim\App;
use Slim\OAuth\OAuthFactory;
use Slim\OAuth\OAuthMiddleware;

$oauthCreds = [
    'github' => [
        'key'       => 'abc',
        'secret'    => '123',
    ]
];

$app = new App();

$oAuthFactory = new OAuthFactory($oauthCreds);

$app->add(new OAuthMiddleware($oAuthFactory));

$app->map(['GET'], '/auth', function ($request, $response, $args) {
    $response->write('<a href="/auth/github">Login via GitHub</a>');

    return $response;
});

$app->run();
```

## Credits

- [Gabriel Baker](https://github.com/gabriel403)

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.
