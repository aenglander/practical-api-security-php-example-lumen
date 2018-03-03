<?php

namespace App\Http;


use Illuminate\Http\Request;
use Jose\Component\Core\Converter\StandardConverter;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Psr\Http\Message\RequestInterface;

class RequestHelper
{
    public static function getJwtStringFromServerRequest(Request $request)
    {
        $auth = $request->headers->get('Authentication');
        return self::getTokenFromHeader($auth);
    }

    public static function getJwtStringFromPsrRequest(RequestInterface $request)
    {
        $auths = $request->getHeader('Authentication');
        $token = $auths[0] ?? null;
        return self::getTokenFromHeader($token);
    }

    public static function getUserAndKeyIdFromRequest(Request $request)
    {
        $token = RequestHelper::getJwtStringFromServerRequest($request);
        if ($token === null) {
            $userId = null;
            $keyId = null;
        } else {
            $converter = new StandardConverter();
            $jwt = (new CompactSerializer($converter))->unserialize($token);
            $claims = $converter->decode($jwt->getPayload());
            $userId = $claims['iss'] ?? null;
            $keyId = $jwt->getSignature(0)->getProtectedHeaderParameter('kid');
        }
        return [$userId, $keyId];
    }

    /**
     * @param $auth
     * @return null
     */
    private static function getTokenFromHeader($auth)
    {
        preg_match("/^Bearer (?P<token>.*)$/", $auth, $matches);
        $token = $matches['token'] ?? null;
        return $token;
    }
}