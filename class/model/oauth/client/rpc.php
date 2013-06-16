<?php

namespace Model\OAuth\Client {

	class RPC implements Driver {

		private $_source;
		private $_token;

		function __construct($source, $token) {
			$this->_source = $source;
			$this->_token = $token;
		}

		function get_username() {
			$s = (array) _CONF('oauth.client')['servers'][$this->_source];
			$rpc = new \Model\RPC($s['api']);
			try {
				$username = $rpc->oauth->get_username($this->_token);
			}
			catch (\Model\RPC\Exception $e) {
				TRACE("error[%d] %s", $e->getCode(), $e->getMessage());
			}

			return $username;
		}

	}

}