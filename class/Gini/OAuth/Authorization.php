<?php

namespace Gini\OAuth {
    class Authorization
    {
        private $_server;
        private $_params;
        private $_session;
        private $_client;
        private $_scope;

        public function __construct()
        {
            // ClientInterface $client, SessionInterface $session, ScopeInterface $scope
            $storageConfig = (array)\Gini\Config::get('oauth.server')['storage'];
            $sessionBackend = $storageConfig['session'] ?: $storageConfig['default'] ?: 'database';
            $this->_session = \Gini\IoC::construct('\Gini\OAuth\Storage\\' . $sessionBackend);
            $clientBackend = $storageConfig['client'] ?: $storageConfig['default'] ?: 'database';
            $this->_client = \Gini\IoC::construct('\Gini\OAuth\Storage\\' . $clientBackend);
            $scopeBackend = $storageConfig['scope'] ?: $storageConfig['default'] ?: 'database';
            $this->_scope = \Gini\IoC::construct('\Gini\OAuth\Storage\\' . $scopeBackend);
        }

        public function handle()
        {
            return new \League\OAuth2\Server\Authorization($this->_client, $this->_session, $this->_scope);
        }

        public function isValid()
        {
            try {
                $server = $this->handle();
                $server->addGrantType(new \League\OAuth2\Server\Grant\AuthCode);
                $this->_params = $server
                    ->getGrantType('authorization_code')
                    ->checkAuthoriseParams();
            } catch (\League\OAuth2\Server\Exception\ClientException $e) {
                \Gini\Logger::of('oauth')->debug('checkAuthoriseParams: {error}!', ['error' => $e->getMessage()]);
                return false;
            }
            return true;
        }

        public function clientDetails()
        {
            return $this->_params['client_details'];
        }

        public function authorize($username)
        {
            $server = $this->handle();
            $server->addGrantType(new \League\OAuth2\Server\Grant\AuthCode);
            // Generate an authorization code
            $code
                = $server->getGrantType('authorization_code')
                ->newAuthoriseRequest('user', $username, $this->_params);
            return \League\OAuth2\Server\Util\RedirectUri::make(
                $this->_params['redirect_uri'],
                [
                    'code' => $code,
                    'state' => isset($this->_params['state']) ? $this->_params['state'] : ''
                ]
            );
        }

        public function deny()
        {
            $server = $this->handle();
            return \League\OAuth2\Server\Util\RedirectUri::make(
                $this->_params['redirect_uri'],
                [
                    'error' => 'access_denied',
                    'error_message' => $server->getExceptionMessage('access_denied'),
                    'state' => isset($this->_params['state']) ? $this->_params['state'] : ''
                ]
            );
        }

        public function issueAccessToken($params = null)
        {
            if (!is_array($params)) {
                $params = $_POST;
            }
            $server = $this->handle();
            $server->addGrantType(new \League\OAuth2\Server\Grant\AuthCode);

            $grantType = new \League\OAuth2\Server\Grant\RefreshToken;
            $server->addGrantType($grantType);
            try {
                // Tell the auth server to issue an access token
                $response = $server->issueAccessToken($params);
            } // Throw an exception because there was a problem with the client's request
            catch (\League\OAuth2\Server\Exception\ClientException $e) {
                $response = array(
                    'error' => $server::getExceptionType($e->getCode()),
                    'error_description' => $e->getMessage()
                );
                // Set the correct header
                array_map(function ($header) {
                    header($header);
                }, $server::getExceptionHttpHeaders(
                    $server::getExceptionType($e->getCode())
                ));
            } // Throw an error when a non-library specific exception has been thrown
            catch (Exception $e) {
                $response = array(
                    'error' => 'undefined_error',
                    'error_description' => $e->getMessage()
                );
            }
            return $response;
        }

        public function setRefreshTokenTTL($refresh_token,$client_id,$ttl_time)
        {
            $expireTime = time()+$ttl_time;
            $this->_session->setRefreshTokenExpireTime($refresh_token, $client_id, $expireTime);
            return $expireTime;
        }
    }
}

