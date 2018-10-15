<?php

namespace App\Http\Middleware;


use App\Exceptions\AuthorizationRequiredException;
use App\Exceptions\InvalidRequestException;
use App\Service\UserService;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\Converter\StandardConverter;
use Jose\Component\Core\JWKSet;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A256CBCHS512;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A256KW;
use Jose\Component\Encryption\Compression\CompressionMethodManager;
use Jose\Component\Encryption\Compression\Deflate;
use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Encryption\JWEDecrypter;
use Jose\Component\Encryption\Serializer\CompactSerializer;

class JWEMiddleware
{

    private $userService;

    public function __construct(UserService $userService)
    {
        $this->userService = $userService;
     }

    public function handle(Request $request, Closure $next)
    {
        $keyWrap = AlgorithmManager::create([new A256KW()]);
        $crypto = AlgorithmManager::create([new A256CBCHS512()]);
        $deflate = CompressionMethodManager::create([new Deflate()]);
        $jweDecrypter = new JWEDecrypter($keyWrap, $crypto, $deflate);
        $compactSerializer = new CompactSerializer(new StandardConverter());

        $user = $this->userService->getCurrentUser();
        if (!$user) {
            throw new AuthorizationRequiredException();
        }

        $keys = ['keys' => []];
        foreach ($user->keys as $kid => $k) {
            $keys['keys'][] = ['kid' => $kid, 'kty' => 'oct', 'k' => $k];
        }
        $jwkSet = JWKSet::createFromKeyData($keys);

        $request->setFormat('jose', ['application/jose']);
        $contentType = $request->getContentType();
        if ($contentType == 'jose') {
            $jwe = $compactSerializer->unserialize($request->getContent());
            $success = $jweDecrypter->decryptUsingKeySet($jwe, $jwkSet, 0);
            if (!$success) {
                throw new InvalidRequestException("Unable to decrypt request. Please verify key and key ID");
            }
            $payload = $jwe->getPayload();
            $contentType = $jwe->getSharedProtectedHeaderParameter('cty');
            $request->initialize($request->query->all(), $request->request->all(), $request->attributes->all(), $request->cookies->all(), $request->files->all(), $request->server->all(), $payload);
            $request->headers->set('Content-Type', $contentType);
        }

        $response = $next($request);
        $content = $response->getContent();

        if ($content) {
            $jweBuilder = new JWEBuilder(new StandardConverter(), $keyWrap, $crypto, $deflate);
            $jwk =  $jwkSet->selectKey('enc');
            $header = $jwk->all();
            unset($header['k']);
            $header += ['cty' => $response->headers->get('Content-Type'), 'alg' => 'A256KW', 'enc' => 'A256CBC-HS512', 'zip' => 'DEF'];

            $jwe = $jweBuilder->create()
                ->withPayload($response->getContent())
                ->withSharedProtectedHeader($header)
                ->addRecipient($jwk)
                ->build();
            $content = $compactSerializer->serialize($jwe);
            $response = new Response($content, $response->getStatusCode(), $response->headers->all());
            $response->header("Content-Type", "application/jose");
        }
        return $response;
    }
}