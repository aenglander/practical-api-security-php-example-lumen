<?php

namespace App\Http\Middleware;


use App\Exceptions\TooManyRequestsException;
use Closure;
use Illuminate\Contracts\Cache\Repository;
use Illuminate\Http\Request;
use Psr\Log\LoggerInterface;
use App\Service\UserService;

class RateLimitMiddleware
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
     * @var UserService
     */
    private $userService;

    public function __construct(Repository $cache, UserService $userService, LoggerInterface $logger)
    {
        $this->cache = $cache;
        $this->userService = $userService;
        $this->logger = $logger;
    }

    public function handle(Request $request, Closure $next)
    {
        if ($request->method() == 'POST' && $request->path() == '/') {
            $seconds = 5;
            $key = sprintf("%s|root-post|%s", $this->userService->getCurrentUser()->id, $this->getCurrentTimeSlice($seconds));
            $this->cache->add($key, 0, 1);
            $total = $this->cache->increment($key);
            if ($total > 2) {
                throw new TooManyRequestsException();
            }
        }
        return $next($request);
    }

    private function getCurrentTimeSlice(int $secondsPerSlice): int
    {
        return floor(time() / $secondsPerSlice) * $secondsPerSlice;
    }


}