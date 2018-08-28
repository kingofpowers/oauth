<?php

namespace Gini\OAuth {

    class Client
    {
        private $_source;
        private $_token;

        private $_driver;

        public function __construct($source)
        {
            $this->_source = $source;
            list($source_name, ) = explode('/', $source);
            $this->_source_name = $source_name;

            $sessionKeyForToken =
                \Gini\Config::get('oauth.client')['session_key']['token'];
            if (isset($_SESSION[$sessionKeyForToken][$source])) {
                $token = $_SESSION[$sessionKeyForToken][$source];
                // \Gini\Logger::of('oauth')->error('invalid token: {error}!', ['error' => $token['error']]);
                if (!isset($token['error'])) {
                    $this->_token = new \League\OAuth2\Client\Token\AccessToken($token);
                }
            }

            $authUri = \Gini\Config::get('oauth.client')['auth_uri'] ?: 'oauth/client/auth';

            if (!$this->_token && \Gini\CGI::route() != $authUri) {
                \Gini\CGI::redirect($authUri, [
                    'source' => $this->_source,
                    'redirect_uri' => URL('', $_GET)
                ]);
            }

            $options = (array) \Gini\Config::get('oauth.client')['servers'][$source_name];

            $driver_class = '\Gini\OAuth\Client\\'.($options['driver']?:'Unknown');

            $this->_driver = \Gini\IoC::construct($driver_class, [
                'clientId' => $options['client_id'],
                'clientSecret' => $options['client_secret'],
                'redirectUri' => URL($authUri, ['source' => $source]),
                'options' => $options
            ]);
        }

        public function getUserName()
        {
            if ($this->_token) {
                $uid = $this->_driver->getUserUid($this->_token);
                list($username, $backend) = \Gini\Auth::parseUserName($uid);

                if ($backend) {
                    $backend .= '%' . $this->_source_name;
                } else {
                    $backend = $this->_source_name;
                }

                return \Gini\Auth::makeUserName($username, $backend);
            }
        }

        public function authorize()
        {
            $this->_driver->authorize();
        }

        public function getUserUid()
        {
            if ($this->_token) {
                return $this->_driver->getUserUid($this->_token);
            }
        }

        public function getUserDetails()
        {
            if ($this->_token) {
                return $this->_driver->getUserDetails($this->_token);
            }
        }

        public function getUserEmail()
        {
            if ($this->_token) {
                return $this->_driver->getUserEmail($this->_token);
            }
        }

        public function getUserScreenName()
        {
            if ($this->_token) {
                return $this->_driver->getUserScreenName($this->_token);
            }
        }

        public function getAccessToken()
        {
            return $this->_token;
        }

        public function fetchAccessToken($grant = 'authorization_code', $params = [])
        {
            $sessionKeyForToken =
                \Gini\Config::get('oauth.client')['session_key']['token'];
            try {
                $this->_token = $this->_driver->getAccessToken($grant, $params);
                $_SESSION[$sessionKeyForToken][$this->_source] = [
                    'access_token' => $this->_token->accessToken,
                    'refresh_token' => $this->_token->refreshToken,
                    'expires' => $this->_token->expires,
                    'uid' => $this->uid,
                ];
            } catch (Exception $e) {
                $this->_token = null;
                $_SESSION[$sessionKeyForToken][$this->_source] = [
                    'error' => $e->getMessage()
                ];
            }
        }
    }

}
