<?php

namespace App\Http\Middleware;


use Closure;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Symfony\Component\HttpKernel\Exception\HttpException;

class ErrorMiddleware
{
    public function handle(Request $request, Closure $next)
    {
        try {
            $response = $next($request);
        } catch (\Exception $e) {
            $content = json_encode(['error' => 'An error occurred: ' . $e->getMessage()]);
            if ($e instanceof HttpException) {
                $statusCode = $e->getStatusCode();
                $headers = $e->getHeaders();
            } else {
                $statusCode = 500;
                $headers = [];
            }
            $headers['content-type'] = 'application/json';
            $response = new Response($content, $statusCode, $headers);
        }
        return $response;
    }
}