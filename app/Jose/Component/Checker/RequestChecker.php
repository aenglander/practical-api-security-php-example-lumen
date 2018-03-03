<?php

namespace App\Jose\Component\Checker;


use Jose\Component\Checker\ClaimChecker;
use Jose\Component\Checker\InvalidClaimException;
use Symfony\Component\HttpFoundation\Request;


final class RequestChecker extends HttpMessageChecker
{
    private $request;

    /**
     * RequestChecker constructor.
     * @param Request $request
     */
    public function __construct(Request $request)
    {
        $this->request = $request;
    }

    /**
     * @param $value
     *
     * @throws \InvalidArgumentException
     * @throws InvalidClaimException
     */
    public function checkClaim($value)
    {
        if (!array_key_exists('method', $value)) {
            throw new \InvalidArgumentException("Sub-claim method not included in request claim");
        } elseif ($value['method'] !== $this->request->getMethod()) {
            throw new InvalidClaimException("Invalid request method", "request.method", $value['method']);
        }

        $content = $this->request->getContent();
        $this->checkBodyHash($value, $content);
    }

    /**
     * @return string
     */
    public function supportedClaim(): string
    {
        return 'request';
    }
}