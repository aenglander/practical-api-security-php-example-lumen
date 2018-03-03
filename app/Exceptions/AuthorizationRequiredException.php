<?php
namespace App\Exceptions;


use Illuminate\Http\Exceptions\HttpResponseException;
use Illuminate\Http\Response;

class AuthorizationRequiredException extends HttpResponseException
{
    public function __construct(string $message = "Authorization is required!")
    {
        parent::__construct(new Response($message, 401));
    }
}