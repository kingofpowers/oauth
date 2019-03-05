<?php

namespace Gini\OAuth {

    class Resource
    {
        private $_isValid;
        private $_server;

        public function __construct($access_token)
        {
            // $_GET, $_POST, $_COOKIE, $_FILES, $_SERVER
            $request = new \League\OAuth2\Server\Util\Request(['access_token'=>$access_token], [], [], [], ['REQUEST_METHOD'=>'GET']);

            $storageConfig = (array) \Gini\Config::get('oauth.server')['storage'];
            $sessionBackend = $storageConfig['session'] ?: $storageConfig['default'] ?: 'database';
            $session = \Gini\IoC::construct('\Gini\OAuth\Storage\\'.$sessionBackend);

            $server = new \League\OAuth2\Server\Resource($session);

            $server->setRequest($request);

            try {
                // check if token is valid
                $this->_isValid = $server->isValid();
            } catch (\League\OAuth2\Server\Exception\InvalidAccessTokenException $e) {
                $this->_isValid = false;
            }

            $this->_server = $server;
        }

        public function isValid()
        {
            return $this->_isValid;
        }

        public function getUserName()
        {
            return $this->isValid() && $this->_server->getOwnerType() == 'user' ? $this->_server->getOwnerId() : false;
        }

        public function getOwnerType() {
            return $this->isValid() ? $this->_server->getOwnerType() : false;
        }

        public function getOwnerId() {
            return $this->isValid() ? $this->_server->getOwnerId() : false;
        }

        public function hasScope($scope)
        {
            return $this->_server->hasScope($scope);
        }
    }

}
