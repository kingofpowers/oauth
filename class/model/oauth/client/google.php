<?php

namespace Model\OAuth\Client {

	class Google implements Driver {

		private $_source;
		private $_token;

		function __construct($source, $token) {
			$this->_source = $source;
			$this->_token = $token;
		}

		function get_username() {

			$path = \Gini\Core::file_exists('vendor/autoload.php', 'oauth');
			require_once($path);

			$s = (array) _CONF('oauth.client')['servers'][$this->_source];
			$client = new \OAuth2\Client($s['client_id'], $s['client_secret']);

			$client->setAccessToken($this->_token);
			$response = $client->fetch($s['api']['get_user']);
			if (!$response['error']) $username = $response["result"]["email"].'|'.$this->_source;
			
			return $username;
		}

	}

}