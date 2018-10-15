<?php

namespace App\Console\Commands;


use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Psr7\Request;
use Illuminate\Console\Command;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\Converter\StandardConverter;
use Jose\Component\Core\JWK;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A256CBCHS512;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A256KW;
use Jose\Component\Encryption\Compression\CompressionMethodManager;
use Jose\Component\Encryption\Compression\Deflate;
use Jose\Component\Encryption\Compression\GZip;
use Jose\Component\Encryption\Compression\ZLib;
use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Encryption\JWEDecrypter;
use Jose\Component\Encryption\Serializer\CompactSerializer as EncryptionCompactSerializer;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\Algorithm\HS384;
use Jose\Component\Signature\Algorithm\HS512;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer as SignatureCompactSerializer;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

class APIClient extends Command
{
    protected $signature = 'api:request 
        {name? : If name is provided, call will be a post with a key/value pair of JSON sent as name/provided-value. Otherwise, it will be a GET call.}
        {--no-nonce : SDo not send X-NONCE header in teh request}
        {--use-nonce= : Use the provided nonce for the X-NONCE header in the request}
        {--no-req-validation : Do not send X-REQUEST-VALIDATION header in the request}
        {--no-auth : SDo not send Authorization header in the request}
        {--user-name=valid-user : Provide a user name. Defaults to allowed-user}
        {--password=password}
        {--no-encryption : Send the request without an encrypted body.}
        {--key-id=key1 : Encryption/Signature Key ID}
        {--key=bc926745ef6c8dda6ed2689d08d5793d7525cb81 : Encryption/Signature Key}
        {--base-url=http://localhost:8080 : Base URL for the request.}
        ';

    protected $description = 'Make a request to the API Server';

    private $converter;
    private $signatureAlgorithmManager;
    private $contentEncryptionAlgorithmManager;
    private $signatureSerializer;
    private $encryptionSerializer;
    private $keyEncryptionAlgorithmManager;
    private $compressionMethodManager;

    public function __construct()
    {
        parent::__construct();
        $this->converter = new StandardConverter();
        $this->signatureSerializer = new SignatureCompactSerializer($this->converter);
        $this->encryptionSerializer = new EncryptionCompactSerializer($this->converter);
        $this->signatureAlgorithmManager = AlgorithmManager::create([new HS256(), new HS384(), new HS512()]);
        $this->contentEncryptionAlgorithmManager = AlgorithmManager::create([new A256CBCHS512()]);
        $this->keyEncryptionAlgorithmManager = AlgorithmManager::create([new A256KW()]);
        $this->compressionMethodManager = CompressionMethodManager::create([new GZip(), new Deflate(), new ZLib()]);
    }

    /**
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function handle()
    {

        list($method, $path, $body, $headers) = $this->getRequestData();
        $request = new Request($method, $path, $headers, $body);
        $this->logRequest($request);

        try {
            $client = $this->getHttpClient();
            $response = $client->send($request);
            $this->logResponse($response);

        } catch (RequestException $e) {
            $this->logResponse($e->getResponse());
        } catch (\Exception $e) {
            $this->error(sprintf("Error processing response: %s", $e->getMessage()));
        }
    }

    private function getHttpClient(): Client
    {
        return new Client(['base_uri' => $this->option('base-url')]);
    }

    private function getRequestJWT(JWK $jwk, string $user): string
    {
        $header = ['cty' => 'JWT', 'alg' => 'HS256'] + $this->getKeyHeaders($jwk);
        $now = time();
        $claims = [
            'iat' => $now,
            'nbf' => $now,
            'exp' => $now,
            'iss' => $user,
            'aud' => 'example-api'
        ];
        $payload = $this->converter->encode($claims);
        $jwsBuilder = new JWSBuilder($this->converter, $this->signatureAlgorithmManager);
        $jws = $jwsBuilder
            ->create()
            ->withPayload($payload)
            ->addSignature($jwk, $header)
            ->build();
        $jwt = $this->signatureSerializer->serialize($jws);
        return $jwt;
    }

    private function getRequestJWS(JWK $jwk, string $request_method, string $path, ?string $request_body, $nonce): string
    {
        $header = ['cty' => 'application/json', 'alg' => 'HS256'] + $this->getKeyHeaders($jwk);
        $claims = [
            'method' => $request_method,
            'path' => $path,
            'nonce' => $nonce
        ];

        if ($request_body !== null) {
            $claims['body_hash_alg'] = 'sha512';
            $claims['body_hash'] = hash('sha512', $request_body);
        }
        $payload = $this->converter->encode($claims);
        $jwsBuilder = new JWSBuilder($this->converter, $this->signatureAlgorithmManager);
        $jws = $jwsBuilder
            ->create()
            ->withPayload($payload)
            ->addSignature($jwk, $header)
            ->build();
        $compactSerializedJWS = $this->signatureSerializer->serialize($jws);
        return $compactSerializedJWS;
    }

    private function getJWK(): JWK
    {
        return JWK::create([
            'kty' => 'oct',
            'kid' => $this->option('key-id'),
            'k' => $this->option('key'),
        ]);
    }

    private function marshall(JWK $jwk, array $data): array
    {
        $payload = $this->converter->encode($data);
        if ($this->requestShouldBeEncrypted()) {
            $header = $this->getKeyHeaders($jwk) + ['cty' => 'application/json', 'alg' => 'A256KW', 'enc' => 'A256CBC-HS512', 'zip' => 'DEF'];
            $jweBuilder = new JWEBuilder($this->converter, $this->keyEncryptionAlgorithmManager, $this->contentEncryptionAlgorithmManager, $this->compressionMethodManager);
            $jwe = $jweBuilder
                ->create()
                ->withPayload($payload)
                ->withSharedProtectedHeader($header)
                ->addRecipient($jwk)
                ->build();
            $contentType = 'application/jose';
            $content = $this->encryptionSerializer->serialize($jwe);
        } else {
            $contentType = 'application/json';
            $content = $payload;
        }
        return [$contentType, $content];
    }

    private function decrypt(JWK $jwk, string $content): array
    {
        $jwe = $this->encryptionSerializer->unserialize($content);
        $decrypter = new JWEDecrypter($this->keyEncryptionAlgorithmManager, $this->contentEncryptionAlgorithmManager, $this->compressionMethodManager);
        if (!$decrypter->decryptUsingKey($jwe, $jwk, 0)) {
            throw new \Exception("Unable to decrypt body");
        }
        $type = $jwe->getSharedProtectedHeaderParameter('cty');
        $payload = $jwe->getPayload();
        return [$type, $payload];
    }

    private function getKeyHeaders(JWK $jwk): array
    {
        $headers = $jwk->all();
        unset($headers['k']);
        return $headers;
    }

    protected function getRequestData(): array
    {
        $name = $this->argument('name');
        $user = $this->option('user-name');
        $pass = $this->option('password');
        $path = '/';
        $jwk = $this->getJWK();
        if ($name === null) {
            $method = "GET";
            $body = null;
            $headers = [];
        } else {
            $method = "POST";
            $data = ['name' => $name];
            list($contentType, $body) = $this->marshall($jwk, $data);
            $headers = ['Content-Type' => $contentType];
        }

        if (!$this->option('no-auth')) {
            $headers['Authorization'] = sprintf("Basic %s", base64_encode(sprintf("%s:%s", $user, $pass)));
        }

        if (!$this->option('no-nonce')) {
            $nonce = $this->option('use-nonce');
            if ($nonce === null) {
                $nonce = base64_encode(random_bytes(32));
            }
            $headers['X-NONCE'] = $nonce;
        } else {
            $nonce = null;
        }
        if (!$this->option('no-req-validation') && env('WITH_REQUEST_VALIDATION', '0') == '1') {
            $headers['X-REQUEST-VALIDATION'] = $this->getRequestJWS($jwk, $method, $path, $body, $nonce);
        }

        return array($method, $path, $body, $headers);
    }


    /***********************************************************************
     * The remaining code is simply for logging information to the console *
     ***********************************************************************/

    protected function logResponse(ResponseInterface $response)
    {
        $response_is_encrypted = str_contains(strtolower($response->getHeader("Content-Type")[0]), 'application/jose');
        $this->comment("\nResponse:\n");
        $this->info(sprintf("HTTP/%s %s %s", $response->getProtocolVersion(), $response->getStatusCode(), $response->getReasonPhrase()));
        foreach ($response->getHeaders() as $key => $values) {
            foreach ($values as $value) {
                $this->info($key . ": " . $value, 'v');
            }
        }

        $content = $response->getBody()->getContents();
        $response->getBody()->rewind();
        $this->info(sprintf("\n%s", $content), $response_is_encrypted ? 'v' : null);

        if ($response_is_encrypted) {
            $this->logEncryptedResponse($response);
        }

    }

    protected function logEncryptedResponse(ResponseInterface $response): void
    {
        $jwk = $this->getJWK();
        try {
            list($contentType, $payload) = $this->decrypt($jwk, $response->getBody()->getContents());
            $response->getBody()->rewind();
            $this->comment(sprintf("\nDecrypted Response: (Content-Type: %s)", $contentType), 'v');
            $this->info(sprintf("\n%s", $payload));
        } catch (\Exception $e) {
            $this->error(sprintf("Unable to parse the response: %s", $e->getMessage()), 'v');
        }
    }

    private function logRequest(RequestInterface $request)
    {
        $this->comment("\nRequest:\n");
        $this->info(sprintf("%s %s HTTP/%s", $request->getMethod(), $request->getUri(), $request->getProtocolVersion()));
        foreach ($request->getHeaders() as $header => $values) {
            foreach ($values as $value) {
                $this->info(sprintf("%s: %s", $header, $value), 'v');
            }
        }

        $encrypted = starts_with(strtolower($request->getHeader('content-type')[0] ?? null), 'application/jose');
        $body = $request->getBody()->getContents();
        $request->getBody()->rewind();
        $this->info(sprintf("\n%s", $body), $encrypted ? 'v' : null);

        if ($encrypted) {
            list($contentType, $decryptedRequest) = $this->decrypt($this->getJWK(), $body);
            $this->comment(sprintf("\nPlaintext Request: (Content-Type: %s)", $contentType), 'v');
            $this->info(sprintf("\n%s", $decryptedRequest));
        }

        if ($request->hasHeader('X-REQUEST-VALIDATION')) {
            $validation = $request->getHeader('X-REQUEST-VALIDATION')[0];
            $this->logTokenClaims($validation, "Validation Claims");
        }

        if ($token = self::getJwtStringFromPsrRequest($request)) {
            $this->logTokenClaims($token, "Auth JWT");
        }
    }

    private function requestShouldBeEncrypted(): bool
    {
        if ($this->option('no-encryption')) {
            return false;
        } else {
            return env('WITH_JWE_ENCRYPTION', '1') === '1';
        }
    }

    private function logTokenClaims($token, $title)
    {
        $this->comment(sprintf("\n%s:\n", $title), 'v');
        foreach ($this->getClaimsFromToken($token) as $key => $value) {
            if (is_array($value)) {
                $this->info(sprintf("%s:", $key), 'v');
                foreach ($value as $subKey => $subValue) {
                    $this->info(sprintf("   %s: %s", $subKey, $subValue), 'v');
                }
            } else {
                $this->info(sprintf("%s: %s", $key, $value), 'v');
            }
        }
    }

    private function getClaimsFromToken(string $token)
    {
        $jws = $this->signatureSerializer->unserialize($token);
        $payload = $jws->getPayload();
        $claims = $this->converter->decode($payload);
        return $claims;
    }

    private static function getJwtStringFromPsrRequest(RequestInterface $request)
    {
        $auths = $request->getHeader('Authentication');
        $token = $auths[0] ?? null;
        return self::getTokenFromHeader($token);
    }

    private static function getTokenFromHeader($auth)
    {
        preg_match("/^X-JWT (?P<token>.*)$/", $auth, $matches);
        $token = $matches['token'] ?? null;
        return $token;
    }


}
