<?php
namespace App\Console\Commands;


use App\Http\RequestHelper;
use App\Jose\Component\Checker\ResponseChecker;
use App\Jose\Component\Checker\StringMatchChecker;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Psr7\Request;
use Illuminate\Console\Command;
use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Checker\ExpirationTimeChecker;
use Jose\Component\Checker\IssuedAtChecker;
use Jose\Component\Checker\NotBeforeChecker;
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
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer as SignatureCompactSerializer;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

class APIClient extends Command
{
    protected $signature = 'api:request 
        {name? : If name is provided, call will be a post with a key/value pair of JSON sent as name/provided-value. Otherwise, it will be a GET call.}
        {--no-jwt : Send no JWT with the request}
        {--no-encryption : Send the request without encryption.}
        {--user-name=valid-user : Provide a user name. Defaults to allowed-user} 
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
     * @throws \Exception
     */
    public function handle()
    {

        list($method, $path, $body, $headers, $nonce) = $this->getRequestData();
        $request = new Request($method, $path, $headers, $body);
        $this->logRequest($request);

        try {
            $client = $this->getHttpClient();
            $response = $client->send($request);
            $this->validateResponse($response, $nonce);
        } catch (RequestException $e) {
            $this->error(sprintf("Server error: %s %s", $e->getResponse()->getStatusCode(), $e->getResponse()->getReasonPhrase()));
            $response = $e->getResponse();
        }

        $this->logResponse($response);
    }

    private function getHttpClient(): Client
    {
        return new Client(['base_uri' => $this->option('base-url')]);
    }

    private function getRequestJWT(JWK $jwk, string $request_method, string $path, ?string $request_body, string $user, string $nonce): string
    {
        $header = ['cty' => 'JWT', 'alg' => 'HS256'] + $this->getKeyHeaders($jwk);
        $now = time();
        $claims = [
            'jti' => $nonce,
            'iat' => $now,
            'nbf' => $now,
            'exp' => $now,
            'iss' => $user,
            'aud' => 'example-api',
            'request' => [
                'method' => $request_method,
                'path' => $path,
            ]
        ];

        if ($request_body !== null) {
            $claims['request']['body_hash_alg'] = 'sha512';
            $claims['request']['body_hash'] = hash('sha512', $request_body);
        }
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

        if (!$this->option('no-jwt')) {
            $nonce = base64_encode(random_bytes(32));
            $jwt = $this->getRequestJWT($jwk, $method, $path, $body, $user, $nonce);
            $headers['Authentication'] = sprintf("Bearer %s", $jwt);
        } else {
            $nonce = null;
        }

        return array($method, $path, $body, $headers, $nonce);
    }

    private function validateResponse(ResponseInterface $response, string $nonce)
    {
        if (!$this->option('no-jwt')) {
            if (!$response->hasHeader('X-JWT')) {
                throw new \Exception("No JWT in response!");
            }
            $token = $response->getHeader('X-JWT')[0];
            $jws = $this->signatureSerializer->unserialize($token);
            $jwk = $this->getJWK();
            (new JWSVerifier($this->signatureAlgorithmManager))->verifyWithKey($jws, $jwk, 0);
            $claims = $this->converter->decode($jws->getPayload());
            ClaimCheckerManager::create([
                new StringMatchChecker('jti', $nonce),
                new StringMatchChecker('iss', 'example-api'),
                new StringMatchChecker('sub', $this->option('user-name')),
                new IssuedAtChecker(5),
                new NotBeforeChecker(5),
                new ExpirationTimeChecker(5),
                new ResponseChecker($response),
            ])->check($claims);
        }
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

        if ($token = $response->getHeader('X-JWT')) {
            $this->logTokenClaims($token[0]);
        }

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

        if ($token = RequestHelper::getJwtStringFromPsrRequest($request)) {
            $this->logTokenClaims($token);
        }
    }

    private function requestShouldBeEncrypted() : bool
    {
        if ($this->option('no-encryption')) {
            return false;
        } else {
            return env('WITH_JWE_ENCRYPTION', '1') === '1';
        }
    }

    private function logTokenClaims($token)
    {
        $this->comment("\nJWT Claims:\n", 'v');
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
}
