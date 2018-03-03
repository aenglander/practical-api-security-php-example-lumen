<?php

namespace App\Jose\Component\Checker;


use Jose\Component\Checker\ClaimChecker;
use Jose\Component\Checker\InvalidClaimException;
use Psr\Http\Message\ResponseInterface;

final class ResponseChecker extends HttpMessageChecker
{

    private $response;

    /**
     * ResponseChecker constructor.
     * @param $response
     */
    public function __construct(ResponseInterface $response)
    {
        $this->response = $response;
    }

    /**
     * @param $value
     *
     * @throws \InvalidArgumentException
     * @throws \Jose\Component\Checker\InvalidClaimException
     */
    public function checkClaim($value)
    {
        $this->checkStatusCodeClaim($value);
        $this->checkCacheControl($value);
        $this->checkContentType($value);
        $this->checkContentLocation($value);
        $content = $this->response->getBody()->getContents();
        $this->response->getBody()->rewind();
        $this->checkBodyHash($value, $content);
    }

    /**
     * @return string
     */
    public function supportedClaim(): string
    {
        return 'response';
    }

    /**
     * @param $value
     * @throws InvalidClaimException
     */
    private function checkStatusCodeClaim($value)
    {
        if ($this->response->getStatusCode() !== $value['status_code'] ?? null) {
            throw new InvalidClaimException("Invalid status code", "response.status_code", $value);
        }
    }

    /**
     * @param $value
     * @throws InvalidClaimException
     */
    private function checkCacheControl($value)
    {
        $this->checkOptionalHeader($this->response, 'Cache-Control', 'cache_control', $value);
    }

    /**
     * @param $value
     * @throws InvalidClaimException
     */
    private function checkContentType($value)
    {
        if ($this->response->getHeader('content-type')[0] !== $value['content_type'] ?? null) {
            throw new InvalidClaimException("Invalid Content-Type", "response.content_type", $value);
        }
    }

    /**
     * @param $value
     * @throws InvalidClaimException
     */
    private function checkContentLocation($value)
    {
        $this->checkOptionalHeader($this->response, 'Location', 'location', $value);
    }
}