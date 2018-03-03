# Practical API Security Example App in Lumen for PHP

## License

See the [Project License](./LICENSE.md) for the project's license.

## Pre-requisites

### PHP

This example utilizes [Lumen](https://lumen.laravel.com/) and 
[Spomky Labs Web Token framework](https://web-token.spomky-labs.com/). As such, you must meet the
[installation requirements for Lumen](https://lumen.laravel.com/docs/5.6/installation#server-requirements) 
and [Spomky Labs Web Token framework](https://web-token.spomky-labs.com/).

The combined requirements are PHP 7.1.3+ with the following extensions:

* OpenSSL
* PDO
* GMP
* MBString

### Composer

This example utilizes [Composer](https://getcomposer.org/) to manage its dependencies. 
So make sure you have [Composer](https://getcomposer.org/) installed on your machine.

### Installation

From the project root directory, execute the compose install command:

```bash
    composer install
``` 

## Running

### Server

The quick and easy way to get the example up and running is to serve it with the built-in PHP development server. From
the project home directory, run the following command:

```bash
    php -S localhost:8080 -t public
```

### Client

Although any HTP client can access the example server, there is a ready made client to properly handle authentication,
request signing and encryption, and response validation and decrypting. The client is a Lumen command. As such, it can
be accessed as such:

```bash
    php artisan api:request
``` 

To see the available options for the client, simply instruct the command to show its help:

```bash
    php artisan api:request -h
``` 

To see detailed information about the request and response, turn on verbose messaging:

```bash
    php artisan api:request -v
``` 

## Playing Around

There are a number of pieces of functionality that are in this example. Toggling them on and off can be accomplished
with environment settings and command options. In lumen, you can change the environment settings via the ```.env```
file. Copy the ```.env.example``` to ```.env``` and make all the changes you like.

Make sure you pay attention to the table below regarding enabling and disabling features. Some features depend on others
to work. Others have stipulations.

| Feature             | Environment Setting          | Command Option  | Requires Features   | Stipulations |
|---------------------|------------------------------|-----------------|---------------------|--------------|
| Request Validation  | ```WITH_JWT_VALIDATION```    | N/A             | N/A                 | Commands without JWT will fail as 401 |
| Replay Prevention   | ```WITH_REPLAY_PREVENTION``` | N/A             | Request Validation  | JWT must be present as it is used as the unique identifier for replay | 
| User Authentication | ```WITH_AUTHENTICATION```    | N/A             | Request Validation  | JWT includes the username as the iss claim. Validating the JWT via the key is used for authentication |
| Rate Limit          | ```WITH_RATE_LIMITING```     | N/A             | User Authentication | GET is not rate limited. Post is rate limited |
| Encryption          | ```WITH_JWE_ENCRYPTION ```   | --no-encryption | User Authentication | User authentication is required to properly determine keys for decryption. Both client and API will abide by the environment setting but client can be overridden by command option |

## Contributing

If you discover an issue with or would like to add additional features to this example app, feel free to 
[fork the repository](https://help.github.com/articles/working-with-forks/) and then
[submit a pull request](https://help.github.com/articles/about-pull-requests/) with your changes.
