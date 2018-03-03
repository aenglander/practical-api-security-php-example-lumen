<?php

namespace App\Providers;

use App\Service\UserService;
use Illuminate\Support\ServiceProvider;

class UserServiceProvider extends ServiceProvider
{
    public function register() {
        $this->app->singleton(UserService::class, function ($app) {
            return new UserService();
        });
    }
}
