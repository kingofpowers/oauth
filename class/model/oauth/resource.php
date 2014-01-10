<?php

namespace Model\OAuth {
    
    class Resource {
        
        private $_isValid;
        private $_server;
        
        function __construct($access_token) {
            
            // $_GET, $_POST, $_COOKIE, $_FILES, $_SERVER
            $request = new \League\OAuth2\Server\Util\Request(['access_token'=>$access_token], [], [], [], ['REQUEST_METHOD'=>'GET']);
            
            $server = new \League\OAuth2\Server\Resource(
                new \Model\OAuth\Storage\Database
            );
            
            $server->setRequest($request);
            
            try {
                // check if token is valid
                $this->_isValid = $server->isValid();                 
            }
            catch (\League\OAuth2\Server\Exception\InvalidAccessTokenException $e) {
                $this->_isValid = false;
            }

            $this->_server = $server;
        }
        
        function isValid() {
            return $this->_isValid;
        }
        
        function getUserName() {
            return $this->isValid() ? $this->_server->getOwnerId() : false;
        }
        
    }
    
}