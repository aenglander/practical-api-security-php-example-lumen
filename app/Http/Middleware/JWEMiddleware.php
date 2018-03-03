<?php

namespace App\Http\Middleware;


use App\Exceptions\InvalidRequestException;
use App\Service\UserService;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Log;
use Jose\Component\Core\JWK;
use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Encryption\JWEDecrypter;
use Jose\Component\Encryption\Serializer\CompactSerializer;
use Closure;

class JWEMiddleware extends JOSEMiddleware
{

    private $jweBuilder;
    private $jweDecrypter;
    private $jwk;
    private $compactSerializer;

    public function __construct(JWEBuilder $jweBuilder, JWEDecrypter $jweDecrypter, CompactSerializer $compactSerializer, UserService $userService)
    {
        parent::__construct($userService);
        $this->jweBuilder = $jweBuilder;
        $this->jweDecrypter = $jweDecrypter;
        $this->compactSerializer = $compactSerializer;
    }

    public function handle(Request $request, Closure $next)
    {
        $request->setFormat('jose', ['application/jose']);
        $contentType = $request->getContentType();
        $jwkSet = $this->getJWKeySet();
        if ($contentType == 'jose') {
            $jwe = $this->compactSerializer->unserialize($request->getContent());
            $success = $this->jweDecrypter->decryptUsingKeySet($jwe, $jwkSet, 0);
            if (!$success) {
                throw new InvalidRequestException("Unable to decrypt request. Please verify key and key ID");
            }
            $payload =  $jwe->getPayload();
            $contentType = $jwe->getSharedProtectedHeaderParameter('cty');
            $request->initialize($request->query->all(), $request->request->all(), $request->attributes->all(), $request->cookies->all(), $request->files->all(), $request->server->all(), $payload);
            $request->headers->set('Content-Type', $contentType);
        }
        $response = $next($request);
        $content = $response->getContent();
        $jwk = $jwkSet->get($this->userService->getCurrentKeyId());
        if ($content) {
            $jwe = $this->jweBuilder->create()
                ->withPayload($response->getContent())
                ->withSharedProtectedHeader($this->getHeader($jwk, $response->headers->get('Content-Type'), 'A256KW', 'A256CBC-HS512', 'DEF'))
                ->addRecipient($jwk)
                ->build();
            $content = $this->compactSerializer->serialize($jwe);
            $response = new Response($content, $response->getStatusCode(), $response->headers->all());
            $response->header("Content-Type", "application/jose");
        }
        return $response;
    }

}