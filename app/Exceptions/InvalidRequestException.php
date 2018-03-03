<?php
namespace App\Exceptions;


use Illuminate\Http\Exceptions\HttpResponseException;
use Illuminate\Http\Response;
use Throwable;

class InvalidRequestException extends HttpResponseException
{
    public function __construct(string $message = "Invalid Request!", Throwable $previous = null)
    {
        parent::__construct(new Response($message, 400));
    }

}