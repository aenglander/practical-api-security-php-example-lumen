<?php

namespace App\Providers;


use Illuminate\Support\ServiceProvider;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\Converter\StandardConverter;
use Jose\Component\Signature\Algorithm\HS512;
use Jose\Component\Signature\JWSBuilder;

class JWSBuilderServiceProvider extends ServiceProvider
{
    public function register() {
        $this->app->singleton(JWSBuilder::class, function ($app) {
            return new JWSBuilder(new StandardConverter(), AlgorithmManager::create([new HS512()]));
        });
    }
}