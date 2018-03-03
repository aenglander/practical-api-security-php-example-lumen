<?php

namespace App\Providers;


use Illuminate\Support\ServiceProvider;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\Converter\StandardConverter;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\Algorithm\HS512;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\JWSVerifier;

class JWSVerifierServiceProvider extends ServiceProvider
{
    public function register()
    {
        $this->app->singleton(JWSVerifier::class, function ($app) {
            return new JWSVerifier(AlgorithmManager::create([new HS256(), new HS512()]));
        });
    }
}