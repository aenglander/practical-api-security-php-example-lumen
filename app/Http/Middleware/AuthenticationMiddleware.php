<?php

namespace App\Http\Middleware;

use App\Exceptions\AuthorizationRequiredException;
use App\Service\UserService;
use Closure;
use Illuminate\Http\Request;

class AuthenticationMiddleware
{

    private $userService;

    public function __construct(UserService $userService)
    {
        $this->userService = $userService;
    }

    public function handle(Request $request, Closure $next)
    {
        $userId = $request->getUser();
        $password = $request->getPassword();
        $user = $this->userService->getUserById($userId);
        if (!$user || !$this->userService->validatePassword($user, $password)) {
            throw new AuthorizationRequiredException();
        }
        $this->userService->setCurrentUser($user);

        return $next($request);
    }
}
