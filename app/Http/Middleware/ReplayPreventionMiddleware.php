<?php

namespace App\Http\Middleware;


use App\Exceptions\InvalidRequestException;
use Closure;
use Illuminate\Contracts\Cache\Repository;
use Illuminate\Http\Request;
use Psr\Log\LoggerInterface;

class ReplayPreventionMiddleware
{
    /**
     * @var LoggerInterface
     */
    private $logger;

    /**
     * @var Repository
     */
    private $cache;

    /**
     * ReplayPrevention constructor.
     * @param $logger
     * @param $cache
     */
    public function __construct(Repository $cache, LoggerInterface $logger)
    {
        $this->cache = $cache;
        $this->logger = $logger;
    }

    public function handle(Request $request, Closure $next)
    {
        $nonce = $request->header('X-NONCE');
        if ($nonce === null) {
            $this->logger->info("No X-NONCE header found in request");
            throw new InvalidRequestException("No X-NONCE header");
        } elseif (!$this->cache->add(hash('sha512', $nonce), 1, 10)) {
            throw new InvalidRequestException("Duplicate Request");
        }
        $response = $next($request);
        $response->headers->set('X-NONCE', $nonce);
        return $response;
    }
}