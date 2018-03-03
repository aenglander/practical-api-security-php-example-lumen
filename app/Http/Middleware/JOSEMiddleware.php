<?php

namespace App\Http\Middleware;

use App\Exceptions\AuthorizationRequiredException;
use App\Service\UserService;
use Closure;
use Illuminate\Http\Request;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;

abstract class JOSEMiddleware
{

    protected $userService;

    public function __construct(UserService $userService)
    {
        $this->userService = $userService;
    }

    public abstract function handle(Request $request, Closure $next);

    protected function getHeader(JWK $jwk, string $cty, string $alg, string $enc = null, string $zip = null): array
    {
        $header = $jwk->all();
        unset($header['k']);
        $header += ['cty' => $cty, 'alg' => $alg];
        if ($enc !== null) $header += ['enc' => $enc];
        if ($zip !== null) $header += ['zip' => $zip];
        return $header;
    }

    protected function getJWKeySet() : JWKSet
    {
        $currentUser = $this->userService->getCurrentUser();
        if ($currentUser == null) {
            throw new AuthorizationRequiredException();
        }

        $keys = ['keys' => []];
        foreach ($currentUser->keys as $kid => $k) {
            $keys['keys'][] = ['kid' => $kid, 'kty' => 'oct', 'k' => $k];
        }
        $keySet = JWKSet::createFromKeyData($keys);
        return $keySet;
    }
}
