<?php

namespace App\Http\Middleware;

use App\Exceptions\AuthorizationRequiredException;
use App\Http\RequestHelper;
use App\Jose\Component\Checker\RequestChecker;
use App\Service\UserService;
use Closure;
use Illuminate\Http\Request;
use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Checker\ExpirationTimeChecker;
use Jose\Component\Checker\IssuedAtChecker;
use Jose\Component\Checker\NotBeforeChecker;
use Jose\Component\Core\Converter\StandardConverter;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Response;

class JWTMiddleware extends JOSEMiddleware
{

    private $jwsBuilder;
    private $jwsVerifier;
    private $compactSerializer;
    private $logger;
    private $jsonConverter;

    public function __construct(JWSBuilder $jwsBuilder, JWSVerifier $jwsVerifier, CompactSerializer $compactSerializer, UserService $userService, LoggerInterface $logger)
    {
        parent::__construct($userService);
        $this->jwsBuilder = $jwsBuilder;
        $this->jwsVerifier = $jwsVerifier;
        $this->compactSerializer = $compactSerializer;
        $this->userService = $userService;
        $this->jsonConverter = new StandardConverter();
        $this->logger = $logger;
    }

    public function handle(Request $request, Closure $next)
    {
        try {
            $token = RequestHelper::getJwtStringFromServerRequest($request);
            if ($token === null) throw new \Exception();
            $jwt = $this->compactSerializer->unserialize($token);
            $jwkSet = $this->getJWKeySet();
            $this->jwsVerifier->verifyWithKeySet($jwt, $jwkSet, 0);
            $claims = $this->getClaims($jwt);
            $this->validateRequest($request, $claims);
        } catch (\Exception $jwtException) {
            throw new AuthorizationRequiredException();
        }

        $response = $next($request);
        $responseJWT = $this->getResponseJWT($response, $claims, $jwkSet);
        $response->headers->set('X-JWT', $this->compactSerializer->serialize($responseJWT));
        return $response;
    }

    private function validateRequest(Request $request, array $claims)
    {
        ClaimCheckerManager::create([
            new IssuedAtChecker(5),
            new NotBeforeChecker(5),
            new ExpirationTimeChecker(5),
            new RequestChecker($request)
        ])->check($claims);
    }

    private function getClaims(JWS $jws)
    {
        $payload = $jws->getPayload();
        $claims = $this->jsonConverter->decode($payload);
        return $claims;
    }

    private function getResponseJWT(Response $response, array $requestClaims, JWKSet $jwkSet)
    {
        $jwk = $jwkSet->get($this->userService->getCurrentKeyId());
        $header = $this->getHeader($jwk, 'JWT', 'HS512');
        $now = time();
        $payload = json_encode([
            'jti' => $requestClaims['jti'] ?? base64_encode(random_bytes(32)),
            'iss' => 'example-api',
            'aud' => $requestClaims['iss'] ?? 'public',
            'iat' => $now,
            'nbf' => $now,
            'exp' => $now,
            'response' => [
                'status_code' => $response->getStatusCode(),
                'cache_control' => $response->headers->get('Cache-Control'),
                'content_type' => $response->headers->get('Content-Type'),
                'body_hash' => hash('sha512', $response->getContent()),
                'body_hash_alg' => 'sha512'
            ]
        ]);
        $jws = $this->jwsBuilder->create()
            ->withPayload($payload)
            ->addSignature($jwk, $header)
            ->build();
        return $jws;
    }
}
