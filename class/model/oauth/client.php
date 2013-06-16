<?php

namespace Model\OAuth\Client {
	
	interface Driver {
		function get_username();
	}

}

namespace Model\OAuth {

	class Client {

		private $_source;
		private $_token;

		private $_driver;

		function __construct($source) {

			if (!isset($_SESSION['oauth.client.token'][$source])) {
				\Model\CGI::redirect('oauth/client/auth', array(
					'source' => $source,
					'redirect_uri' => URL('', $_GET),
				));
			}

			$this->_source = $source;

			$token = $_SESSION['oauth.client.token'][$source];
			if ($token[0] == '@') {
				$error = mb_substr($token, 1);
				TRACE('invalid token: '.$error);
				return;
			}

			$this->_token = $token;

			$s = (array) _CONF('oauth.client')['servers'][$source];

			$driver_class = '\\Model\\OAuth\\Client\\'.($s['driver']?:'rpc');
			$this->_driver = new $driver_class($source, $token);
		}

		function get_username() {
			if (!$this->_driver) return;
			$username = $this->_driver->get_username();
			if ($username) {
				$username .= '%' . $this->_source;
			}

			return $username;
		}

		function get_access_token() {
			return $this->_token;
		}

	}

}