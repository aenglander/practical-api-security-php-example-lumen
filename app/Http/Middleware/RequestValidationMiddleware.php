<?php

namespace App\Http\Middleware;

use App\Exceptions\InvalidRequestException;
use App\Service\UserService;
use Closure;
use Illuminate\Http\Request;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\Converter\StandardConverter;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\Algorithm\HS512;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Psr\Log\LoggerInterface;

class RequestValidationMiddleware
{

    private $logger;
    private $userService;

    public function __construct(UserService $userService, LoggerInterface $logger)
    {
        $this->userService = $userService;
        $this->logger = $logger;
    }

    public function handle(Request $request, Closure $next)
    {
        if (!$request->hasHeader('X-REQUEST-VALIDATION')) {
            throw new InvalidRequestException('No X-REQUEST-VALIDATION header');
        }
        try {
            $compactSerializer = new CompactSerializer(new StandardConverter());
            $jws = $compactSerializer->unserialize($request->headers->get('X-REQUEST-VALIDATION'));

            $keys = ['keys' => []];
            foreach ($this->userService->getCurrentUser()->keys as $kid => $k) {
                $keys['keys'][] = ['kid' => $kid, 'kty' => 'oct', 'k' => $k];
            }
            $jwkSet = JWKSet::createFromKeyData($keys);

            $jwsVerifier = new JWSVerifier(AlgorithmManager::create([new HS256(), new HS512()]));
            if (!$jwsVerifier->verifyWithKeySet($jws, $jwkSet, 0)) {
                throw new \Exception("Invalid Request Validation!");
            }

            $payload = $jws->getPayload();
            $claims = (new StandardConverter())->decode($payload);

            if (!array_key_exists('method', $claims)) {
                throw new \InvalidArgumentException("method not included in request validation");
            } elseif ($claims['method'] !== $request->getMethod()) {
                throw new \Exception("Invalid request method");
            }

            if (!array_key_exists('path', $claims)) {
                throw new \InvalidArgumentException("path not included in request validation");
            } elseif ($claims['path'] !== $request->getPathInfo()) {
                throw new \Exception("Invalid request path");
            }

            if (!array_key_exists('nonce', $claims)) {
                throw new \InvalidArgumentException("nonce method not included in request validation");
            } elseif ($claims['nonce'] !== $request->headers->get('X-NONCE')) {
                throw new \Exception("Invalid request nonce header");
            }

            $content = $request->getContent();

            $hasContent = strlen($content) > 0;
            if (!array_key_exists('body_hash_alg', $claims) && $hasContent) {
                throw new \InvalidArgumentException("body_hash_alg not included in request claim when request has body");
            } elseif (!array_key_exists('body_hash', $claims) && $hasContent) {
                throw new \InvalidArgumentException("body_hash not included in request claim when request has body");
            } elseif (array_key_exists('body_hash', $claims) && !$hasContent) {
                throw new \InvalidArgumentException("body_hash included in request claim when request has no body");
            } elseif ($hasContent && hash($claims['body_hash_alg'], $content) !== $claims['body_hash']) {
                throw new \Exception("Body hash does not match claim");
            }

        } catch (\Exception $jwtException) {
            throw new InvalidRequestException($jwtException->getMessage());
        }

        return $next($request);
    }

 }
