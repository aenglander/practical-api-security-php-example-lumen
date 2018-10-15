<?php

namespace App\Http\Middleware;

use App\Exceptions\InvalidRequestException;
use App\Service\UserService;
use Closure;
use Illuminate\Http\Request;
use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Checker\ExpirationTimeChecker;
use Jose\Component\Checker\IssuedAtChecker;
use Jose\Component\Checker\NotBeforeChecker;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\Converter\StandardConverter;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\Algorithm\HS512;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;

class JWTMiddleware
{
    private $userService;

    public function __construct(UserService $userService)
    {
        $this->userService = $userService;
    }

    public function handle(Request $request, Closure $next)
    {
        try {
            $auth = $request->headers->get('Authentication');
            preg_match("/^X-JWT (?P<token>.*)$/", $auth, $matches);
            $token = $matches['token'] ?? null;
            if ($token === null) throw new \Exception("Unable to get request authentication data");

            $compactSerializer = new CompactSerializer(new StandardConverter());
            $jwt = $compactSerializer->unserialize($token);

            $keys = ['keys' => []];
            foreach ($this->userService->getCurrentUser()->keys as $kid => $k) {
                $keys['keys'][] = ['kid' => $kid, 'kty' => 'oct', 'k' => $k];
            }
            $jwkSet = JWKSet::createFromKeyData($keys);

            $jwsVerifier = new JWSVerifier(AlgorithmManager::create([new HS256(), new HS512()]));
            if (!$jwsVerifier->verifyWithKeySet($jwt, $jwkSet, 0)) {
                throw new \Exception("Invalid JWT!");
            }

            $payload = $jwt->getPayload();
            $claims = (new StandardConverter())->decode($payload);

            ClaimCheckerManager::create([
                new IssuedAtChecker(5),
                new NotBeforeChecker(5),
                new ExpirationTimeChecker(5)
            ])->check($claims);

        } catch (\Exception $jwtException) {
            throw new InvalidRequestException("Invalid Request!", $jwtException);
        }
        return $next($request);
    }
}