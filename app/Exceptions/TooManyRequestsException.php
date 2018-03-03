<?php

namespace App\Exceptions;


use Illuminate\Http\Exceptions\HttpResponseException;
use Symfony\Component\HttpFoundation\Response;

class TooManyRequestsException extends HttpResponseException
{
    public function __construct()
    {
        parent::__construct(new Response("Too many requests!", 429));
    }
}