<?php

namespace App\Http\Middleware;

use App\Exceptions\AuthorizationRequiredException;
use App\Http\RequestHelper;
use App\Service\UserService;
use Closure;
use Jose\Component\Core\Converter\StandardConverter;
use Jose\Component\Signature\Serializer\CompactSerializer;

class AuthenticationMiddleware
{

    private $userService;
    private $compactSerializer;
    private $jsonConverter;

    public function __construct(UserService $userService, CompactSerializer $compactSerializer)
    {
        $this->userService = $userService;
        $this->compactSerializer = $compactSerializer;
        $this->jsonConverter = new StandardConverter();
    }

    public function handle($request, Closure $next)
    {
        list($userId, $keyId) = RequestHelper::getUserAndKeyIdFromRequest($request);
        $user = $this->userService->getUserById($userId);
        if (!$user || !array_key_exists($keyId, $user->keys)) {
            throw new AuthorizationRequiredException();
        }
        $this->userService->setCurrentUser($user);
        $this->userService->setCurrentKeyId($keyId);

        return $next($request);
    }
}
