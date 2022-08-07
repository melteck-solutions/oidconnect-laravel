<?php

namespace Furdarius\OIDConnect\Http\Controllers;

use Furdarius\OIDConnect\Exception\AuthenticationException;
use Furdarius\OIDConnect\Exception\TokenStorageException;
use Furdarius\OIDConnect\TokenRefresher;
use Furdarius\OIDConnect\TokenStorage;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller as BaseController;
use JsonSerializable;
use Laravel\Socialite\Facades\Socialite;
use Laravel\Socialite\Two\User;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Token\Plain;
use Symfony\Component\HttpFoundation\RedirectResponse;

class AuthController extends BaseController
{
    /**
     *
     * @return RedirectResponse
     */
    public function redirect(): RedirectResponse
    {
        /** @var RedirectResponse $redirectResponse */
        return Socialite::with('myoidc')->stateless()->redirect();
    }

    /**
     * @param Request      $request
     * @param TokenStorage $storage
     *
     * @return JsonResponse
     */
    public function callback(Request $request, TokenStorage $storage): JsonResponse
    {
        // TODO: handle CORS more elegant way
        if ($request->getMethod() === 'OPTIONS') {
            return $this->responseJson([])
                ->header('Access-Control-Allow-Origin', '*')
                ->header('Access-Control-Allow-Methods', strtoupper($request->headers->get('Access-Control-Request-Method')))
                ->header('Access-Control-Allow-Headers', $request->headers->get('Access-Control-Request-Headers'));
        }

        /** @var User $user */
        $user = Socialite::with('myoidc')->stateless()->user();

        if (!$storage->saveRefresh($user['sub'], $user['iss'], $user->refreshToken)) {
            throw new TokenStorageException("Failed to save refresh token");
        }

        return $this->responseJson([
            'name' => $user->getName(),
            'email' => $user->getEmail(),
            'token' => $user->token,
        ]);
    }

    /**
     * @param array|JsonSerializable $data
     * @param int                     $status
     * @param array                   $headers
     *
     * @return JsonResponse
     */
    protected function responseJson(array|JsonSerializable $data, int $status = 200, array $headers = []): JsonResponse
    {
        return response()->json($data, $status, $headers)
            ->setEncodingOptions(JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)
            ->header('Access-Control-Allow-Origin', '*');
    }

    /**
     * @param Request        $request
     * @param TokenRefresher $refresher
     * @param Parser         $parser
     *
     * @return AuthenticationException|JsonResponse
     */
    public function refresh(Request $request, TokenRefresher $refresher, Parser $parser): JsonResponse|AuthenticationException
    {
        $data = $request->json()->all();

        if (!isset($data['token'])) {
            return new AuthenticationException("Failed to get JWT token from input");
        }

        $jwt = $data['token'];
        /**
         * We cant get claims from Token interface, so call claims method implicitly
         * link: https://github.com/lcobucci/jwt/pull/186
         *
         * @var $token Plain
         */
        $token = $parser->parse($jwt);

        $claims = $token->claims();

        $sub = $claims->get('sub');
        $iss = $claims->get('iss');

        $refreshedIDToken = $refresher->refreshIDToken($sub, $iss);

        return $this->responseJson([
            'token' => $refreshedIDToken,
        ]);
    }
}
