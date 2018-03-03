<?php

/*
|--------------------------------------------------------------------------
| Application Routes
|--------------------------------------------------------------------------
|
| Here is where you can register all of the routes for an application.
| It is a breeze. Simply tell Lumen the URIs it should respond to
| and give it the Closure to call when that URI is requested.
|
*/

$router->get('/', function () use ($router) {
    return new \Illuminate\Http\JsonResponse(['Hello' => 'World!']);
});

$router->post('/', function (\Illuminate\Http\Request $request) use ($router) {
    $this->validate($request, ['name' => 'required|min:3|max:255']);
    return new \Illuminate\Http\JsonResponse(['Hello' => $request->json('name')]);
});
