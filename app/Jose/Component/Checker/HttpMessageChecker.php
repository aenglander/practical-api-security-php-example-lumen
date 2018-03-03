<?php

namespace App\Jose\Component\Checker;


use Jose\Component\Checker\ClaimChecker;
use Jose\Component\Checker\InvalidClaimException;
use Psr\Http\Message\MessageInterface;

abstract class HttpMessageChecker implements ClaimChecker
{

    /**
     * @param $value
     * @param $content
     * @throws InvalidClaimException
     */
    protected function checkBodyHash($value, $content): void
    {
        $hasContent = strlen($content) > 0;
        if (!array_key_exists('body_hash_alg', $value) && $hasContent) {
            throw new \InvalidArgumentException("Sub-claim body_hash_alg not included in request claim when request has body");
        } elseif (!array_key_exists('body_hash', $value) && $hasContent) {
            throw new \InvalidArgumentException("Sub-claim body_hash not included in request claim when request has body");
        } elseif (array_key_exists('body_hash', $value) && !$hasContent) {
            throw new \InvalidArgumentException("Sub-claim body_hash included in request claim when request has no body");
        } elseif ($hasContent && hash($value['body_hash_alg'], $content) !== $value['body_hash']) {
            throw new InvalidClaimException("Body hash does not match claim", sprintf('%s.body_hash', $this->supportedClaim()), $value['body_hash']);
        }
    }

    /**
     * @param MessageInterface $message
     * @param $value
     * @throws InvalidClaimException
     */
    protected function checkOptionalHeader(MessageInterface $message, $header, $claim, $value): void
    {
        if ($message->hasHeader($header) && !array_key_exists($claim, $value)) {
            throw new InvalidClaimException(sprintf("Response has %s header but no claim", $header), sprintf('%s.%w', $this->supportedClaim(), $claim), $value);
        } elseif (array_key_exists($claim, $value)) {

            $header = $message->hasHeader($header) ? $message->getHeader($header)[0] : null;
            $claimValue = $value[$claim];
            if ($header !== $claimValue) {
                throw new InvalidClaimException(sprintf("%s header did not match claim value \"%s\"", $header, $claimValue), sprintf('%s.%w', $this->supportedClaim(), $claim), $value);
            }
        }
    }

}