<?php

namespace Gini\OAuth {

    class Authorization
    {
        private $_server;
        private $_params;

        function __construct()
        {
            $db = \Gini\IoC::construct('\Gini\OAuth\Storage\Database');

            // ClientInterface $client, SessionInterface $session, ScopeInterface $scope
            $storageConfig = (array) \Gini\Config::get('oauth.server')['storage'];

            $sessionBackend = $storageConfig['session'] ?: $storageConfig['default'] ?: 'database';
            $session = \Gini\IoC::construct('\Gini\OAuth\Storage\\'.$sessionBackend);

            $clientBackend = $storageConfig['client'] ?: $storageConfig['default'] ?: 'database';
            $client = \Gini\IoC::construct('\Gini\OAuth\Storage\\'.$clientBackend);

            $scopeBackend = $storageConfig['scope'] ?: $storageConfig['default'] ?: 'database';
            $scope = \Gini\IoC::construct('\Gini\OAuth\Storage\\'.$scopeBackend);

            $server = new \League\OAuth2\Server\Authorization($client, $session, $scope);
            $server->addGrantType(new \League\OAuth2\Server\Grant\AuthCode);

            $this->_server = $server;

        }

        function isValid()
        {
            $server = $this->_server;

            // Enable the authorization code grant type
            $server->addGrantType(new \League\OAuth2\Server\Grant\ClientCredentials);

            try {
                $this->_params = $server
                    ->getGrantType('authorization_code')
                    ->checkAuthoriseParams();
            } catch (\League\OAuth2\Server\Exception\ClientException $e) {
                \Gini\Logger::of('oauth')->debug('checkAuthoriseParams: {error}!', ['error' => $e->getMessage()]);

                return false;
            }

            return true;
        }

        function clientDetails()
        {
            return $this->_params['client_details'];
        }

        function authorize($username)
        {
            $server = $this->_server;

            // Generate an authorization code
            $code
                = $server->getGrantType('authorization_code')
                    ->newAuthoriseRequest('user', $username, $this->_params);

            return \League\OAuth2\Server\Util\RedirectUri::make(
                $this->_params['redirect_uri'],
                [
                    'code'  =>  $code,
                    'state' =>  isset($this->_params['state']) ? $this->_params['state'] : ''
                ]
            );

        }

        function deny()
        {
            $server = $this->_server;

            return \League\OAuth2\Server\Util\RedirectUri::make(
                $this->_params['redirect_uri'],
                [
                    'error' =>  'access_denied',
                    'error_message' =>  $server->getExceptionMessage('access_denied'),
                    'state' =>  isset($this->_params['state']) ? $this->_params['state'] : ''
                ]
            );
        }

        function issueAccessToken()
        {
            $server = $this->_server;

            $server->addGrantType(new \League\OAuth2\Server\Grant\RefreshToken);

            try {
                // Tell the auth server to issue an access token
                $response = $server->issueAccessToken();
            }
            // Throw an exception because there was a problem with the client's request
            catch (\League\OAuth2\Server\Exception\ClientException $e) {

                $response = array(
                    'error' =>  $server::getExceptionType($e->getCode()),
                    'error_description' => $e->getMessage()
                );

                // Set the correct header
                header($server::getExceptionHttpHeaders(
                    $server::getExceptionType($e->getCode())
                ));

            }
            // Throw an error when a non-library specific exception has been thrown
            catch (Exception $e) {

                $response = array(
                    'error' =>  'undefined_error',
                    'error_description' => $e->getMessage()
                );
            }

            return $response;
        }

    }

}
