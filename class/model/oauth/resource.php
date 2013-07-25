<?php

namespace Model\OAuth {

	class Resource {

		private $_storage;
		private $_server;

		private $_request;
		private $_response;

		private $_verified;

		function __construct($access_token) {

			$path = \Gini\Core::file_exists('vendor/autoload.php', 'oauth');
			require_once($path);

			$this->_storage = new \Model\OAuth\Storage\Database();
			$this->_server = new \OAuth2_Server($this->_storage);

			$this->_request = new \OAuth2_Request(['access_token'=>$access_token]);
			$this->_response = new \OAuth2_Response();
			
			$this->_verified = $this->_server->verifyResourceRequest($this->_request, $this->_response);

		}

		function verified() {
			return $this->_verified;
		}

		function get_username() {
			if (!$this->_verified) return null;
			$token_data = $this->_server->getAccessTokenData($this->_request, $this->_response);
			return $token_data['user_id'];
		}

	}


}