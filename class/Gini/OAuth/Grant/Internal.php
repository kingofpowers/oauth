<?php

namespace Gini\OAuth\Grant;

use League\OAuth2\Server\Grant\GrantTypeInterface;
use League\OAuth2\Server\Grant\GrantTrait;
use League\OAuth2\Server\Util\SecureKey;

/**
 * Referesh token grant
 */
class Internal implements GrantTypeInterface
{

    use GrantTrait;

    /**
     * Grant identifier
     * @var string
     */
    protected $identifier = 'internal';

    /**
     * Response type
     * @var string
     */
    protected $responseType = null;

    /**
     * AuthServer instance
     * @var AuthServer
     */
    protected $authServer = null;

    /**
     * Access token expires in override
     * @var int
     */
    protected $accessTokenTTL = null;

    /**
     * Complete the refresh token grant
     * @param  null|array $inputParams
     * @return array
     */
    public function completeFlow($inputParams = null)
    {
        // Create a new session
        $sessionId = $this->authServer->getStorage('session')->createSession(
            $inputParams['client_id'],
            $inputParams['owner_type'],
            $inputParams['owner_id']
        );

        // A session ID was returned so update it with an access token and remove the authorisation code
        $accessToken = SecureKey::make();
        $accessTokenExpiresIn = ($this->accessTokenTTL !== null)
            ? $this->accessTokenTTL
            : $this->authServer->getAccessTokenTTL();
        $accessTokenExpires = time() + $accessTokenExpiresIn;

        // Create an access token
        $accessTokenId = $this->authServer->getStorage('session')->associateAccessToken($sessionId, $accessToken, $accessTokenExpires);

        if ($inputParams['scope']) {
            $scopes = explode($this->authServer->getScopeDelimeter(), $inputParams['scope']);
            for ($i = 0; $i < count($scopes); $i++) {
                $scopes[$i] = trim($scopes[$i]);
                if ($scopes[$i] === '') unset($scopes[$i]); // Remove any junk scopes
            }

            foreach ($scopes as $scope) {
                $scopeDetails = $this->authServer->getStorage('scope')->getScope($scope, $inputParams['client_id'], $this->identifier);
                $this->authServer->getStorage('session')->associateScope($accessTokenId, $scopeDetails['id']);
            }
        }

        $response = array(
            'access_token'  =>  $accessToken,
            'token_type'    =>  'Bearer',
            'expires'       =>  $accessTokenExpires,
            'expires_in'    =>  $accessTokenExpiresIn
        );

        // Associate a refresh token if set
        if ($this->authServer->hasGrantType('refresh_token')) {
            $refreshToken = SecureKey::make();
            $refreshTokenTTL = time() + $this->authServer->getGrantType('refresh_token')->getRefreshTokenTTL();
            $this->authServer->getStorage('session')
                ->associateRefreshToken(
                    $accessTokenId,
                    $refreshToken,
                    $refreshTokenTTL,
                    $inputParams['client_id']
                );
            $response['refresh_token'] = $refreshToken;
        }

        return $response;
    }
}
