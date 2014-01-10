<?php

namespace Model\OAuth {

	class Client {

		private $_source;
		private $_token;

		private $_driver;

		function __construct($source) {

			$this->_source = $source;

            if (isset($_SESSION['oauth.client.token'][$source])) {
    			$token = $_SESSION['oauth.client.token'][$source];
    			if (isset($token['error'])) {
    				TRACE('invalid token: '.$token['error']);
    			}
                else {
        			$this->_token = new \League\OAuth2\Client\Token\AccessToken($token);
                }
            }

			$options = (array) _CONF('oauth.client')['servers'][$source];

			$driver_class = '\\Model\\OAuth\\Client\\'.($options['driver']?:'Unknown');
            
			$this->_driver = new $driver_class([
                'clientId' => $options['client_id'],
                'clientSecret' => $options['client_secret'],
                'redirectUri' => URL('oauth/client/auth', ['source'=>$source]),
                'options' => $options
			]);
		}

		function getUserName() {
            
            if (!$this->_token) {
                \Model\CGI::redirect('oauth/client/auth', [
                    'source' => $this->_source,
                    'redirect_uri' => URL('', $_GET)
                ]);
            }
            
			$uid = $this->_driver->getUserUid($this->_token);
            list($username, $backend) = \Model\Auth::parse_username($uid);
            
            if ($backend) {
                $backend .= '%' . $this->_source;
            }
            else {
                $backend = $this->_source;
            }
            
            return \Model\Auth::make_username($username, $backend);
		}

        function authorize() {
            $this->_driver->authorize();
        }
        
		function fetchAccessToken($grant = 'authorization_code', $params = []) {
            try {
                $this->_token = $this->_driver->getAccessToken($grant, $params);
 			    $_SESSION['oauth.client.token'][$this->_source] = [
 			        'access_token' => $this->_token->accessToken,
                    'refresh_token' => $this->_token->refreshToken,
                    'expires' => $this->_token->expires,
                    'uid' => $this->uid,
 			    ];
            }
            catch (Exception $e) {
                $this->_token = null;
                $_SESSION['oauth.client.token'][$this->_source] = [
                    'error' => $e->getMessage()
                ];
            }
		}

	}

}