<?php

namespace App\Providers;


use Illuminate\Support\ServiceProvider;
use Jose\Component\Core\Converter\StandardConverter;
use Jose\Component\Encryption\Serializer\CompactSerializer;

class EncryptionCompactSerializerServiceProvider extends ServiceProvider
{
    public function register() {
        $this->app->singleton(CompactSerializer::class, function ($app) {
            return new CompactSerializer(new StandardConverter());
        });
    }
}