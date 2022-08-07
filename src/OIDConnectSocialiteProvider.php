<?php

namespace Furdarius\OIDConnect;

use Furdarius\OIDConnect\Exception\TokenRequestException;
use Illuminate\Http\Request;
use Illuminate\Support\Arr;
use JetBrains\PhpStorm\ArrayShape;
use JetBrains\PhpStorm\Pure;
use Laravel\Socialite\Two\AbstractProvider;
use Laravel\Socialite\Two\InvalidStateException;
use Laravel\Socialite\Two\ProviderInterface;
use Laravel\Socialite\Two\User;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Token\Plain;

class OIDConnectSocialiteProvider extends AbstractProvider implements ProviderInterface
{
    /**
     * The scopes being requested.
     *
     * @var array
     */
    protected $scopes = [
        'openid',
        'email',
        'profile',
        'offline_access',
    ];

    /**
     * The separating character for the requested scopes.
     *
     * @var string
     */
    protected $scopeSeparator = ' ';

    /**
     * JWT Token parser instance.
     *
     * @var Parser
     */
    protected Parser $parser;
    /**
     * @var string
     */
    private string $authUrl;
    /**
     * @var string
     */
    private string $tokenUrl;

    /**
     * Create a new provider instance.
     *
     * @param Request $request
     * @param Parser $parser
     * @param  string                   $clientId
     * @param  string                   $clientSecret
     * @param  string                   $redirectUrl
     * @param  string                   $authUrl
     * @param  string                   $tokenUrl
     */
    #[Pure]
    public function __construct(
        Request $request,
        Parser $parser,
        string $clientId,
        string $clientSecret,
        string $redirectUrl,
        string $authUrl,
        string $tokenUrl
    ) {
        parent::__construct($request, $clientId, $clientSecret, $redirectUrl);

        $this->parser = $parser;
        $this->authUrl = $authUrl;
        $this->tokenUrl = $tokenUrl;
    }

    /**
     * {@inheritdoc}
     */
    public function user(): User|\Laravel\Socialite\Contracts\User|null
    {
        if ($this->hasInvalidState()) {
            throw new InvalidStateException;
        }

        $response = $this->getAccessTokenResponse($this->getCode());

        if (!empty($response['error'])) {
            throw new TokenRequestException($response['error']);
        }

        $token = $response['id_token'];

        $user = $this->mapUserToObject($this->getUserByToken($token));

        return $user->setToken($token)
            ->setRefreshToken(Arr::get($response, 'refresh_token'))
            ->setExpiresIn(Arr::get($response, 'expires_in'));
    }

    /**
     * {@inheritdoc}
     */
    protected function mapUserToObject(array $user): User
    {
        return (new User)->setRaw($user)->map([
            'id' => $user['sub'],
            'sub' => $user['sub'],
            'iss' => $user['iss'],
            'nickname' => $user['name'],
            'name' => $user['name'],
            'email' => $user['email'],
        ]);
    }

    /**
     * {@inheritdoc}
     */
    #[ArrayShape(['sub' => "mixed|null", 'iss' => "mixed|null", 'name' => "mixed|null", 'email' => "mixed|null"])]
    protected function getUserByToken($token): array
    {
        /**
         * We cant get claims from Token interface, so call claims method implicitly
         * link: https://github.com/lcobucci/jwt/pull/186
         *
         * @var $plainToken Plain
         */
        $plainToken = $this->parser->parse($token);

        $claims = $plainToken->claims();

        return [
            'sub' => $claims->get('sub'),
            'iss' => $claims->get('iss'),
            'name' => $claims->get('name'),
            'email' => $claims->get('email'),
        ];
    }

    /**
     * {@inheritdoc}
     */
    #[ArrayShape(['client_id' => "string", 'client_secret' => "string", 'code' => "string", 'redirect_uri' => "string", 'grant_type' => "string"])]
    protected function getTokenFields($code): array
    {
        return [
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
            'code' => $code,
            'redirect_uri' => $this->redirectUrl,
            'grant_type' => 'authorization_code',
        ];
    }

    /**
     * {@inheritdoc}
     */
    protected function getAuthUrl($state): string
    {
        return $this->buildAuthUrlFromBase($this->authUrl, $state);
    }

    /**
     * {@inheritdoc}
     */
    protected function getTokenUrl(): string
    {
        return $this->tokenUrl;
    }
}
