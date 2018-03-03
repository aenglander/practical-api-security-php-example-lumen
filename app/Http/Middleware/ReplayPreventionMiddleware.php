<?php

namespace App\Http\Middleware;


use App\Exceptions\AuthorizationRequiredException;
use App\Exceptions\InvalidRequestException;
use App\Http\RequestHelper;
use Closure;
use Illuminate\Auth\Access\AuthorizationException;
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
        $token = RequestHelper::getJwtStringFromServerRequest($request);
        if ($token === null) {
            $this->logger->info("No JWT found in request");
            throw new AuthorizationRequiredException();
        } elseif (!$this->cache->add(hash('sha512', $token), 1, 10)) {
            throw new InvalidRequestException();
        }
        return $next($request);
    }
}