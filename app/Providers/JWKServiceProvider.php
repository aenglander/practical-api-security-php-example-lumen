<?php

namespace App\Providers;


use Illuminate\Support\ServiceProvider;
use Jose\Component\Core\JWK;

class JWKServiceProvider extends ServiceProvider
{
    public function register() {
        $this->app->singleton(JWK::class, function ($app) {
            return JWK::create([
                'kty' => 'oct',
                'kid' => config('jose_key_id'),
                'k' => config('jose_key_value'),
            ]);
        });
    }

}