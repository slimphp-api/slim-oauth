# Slim Framework OAuth Middleware

This repository contains a Slim Framework OAuth middleware.

Enables you to authenticate using various OAuth providers.

## Install

Via Composer

``` bash
$ composer require gabriel403/slim-oauth
```

Requires Slim 3.0.0 or newer.

## Usage

```php
<?php
use Slim\App;
use Slim\OAuth\OAuthFactory;
use Slim\OAuth\OAuthMiddleware;

$oAuthCreds = [
    'github' => [
        'key'       => 'abc',
        'secret'    => '123',
    ]
];

$app = new App();

$app['OAuthFactory'] = new OAuthFactory($oAuthCreds);

$app->add(new OAuthMiddleware($app['OAuthFactory']));

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
