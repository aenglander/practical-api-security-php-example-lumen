<?php

namespace App\Jose\Component\Checker;


use Jose\Component\Checker\ClaimChecker;
use Jose\Component\Checker\InvalidClaimException;

/**
 * Matcher to verify that value of a claims is equal to the expected value.
 * @package App\Jose\Component\Checker
 */
final class StringMatchChecker implements ClaimChecker
{
    private $claim;
    private $expected;

    /**
     * @param string $claim
     * @param string $expected
     */
    public function __construct(string $claim, string $expected)
    {
        $this->claim = $claim;
        $this->expected = $expected;
    }

    /**
     * @param string $value
     *
     * @throws \InvalidArgumentException
     * @throws InvalidClaimException
     */
    public function checkClaim($value)
    {
        if ($this->expected !== $value) {
            throw new InvalidClaimException("Values not equals", $this->claim, $value);
        }
    }

    /**
     * @return string
     */
    public function supportedClaim(): string
    {
        return $this->claim;
    }
}