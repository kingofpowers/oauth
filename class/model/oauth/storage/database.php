<?php

namespace Model\OAuth\Storage {

	class Database 
		implements 
			\OAuth2_Storage_AuthorizationCodeInterface,
    		\OAuth2_Storage_AccessTokenInterface, \OAuth2_Storage_ClientCredentialsInterface,
   			\OAuth2_Storage_UserCredentialsInterface, \OAuth2_Storage_RefreshTokenInterface, 
   			\OAuth2_Storage_JWTBearerInterface,
   			\OAuth2_Storage_ScopeInterface {
		
   		private $_db;
   		private $_table;

		function __construct($connection=NULL, $config = array()) {
			$this->_db = \Model\Database::db($connection);
			$this->_table = array_merge([
				'client' => '_oauth_client',
				'client_scope' => '_oauth_client_scope',
				'access_token' => '_oauth_access_token',
	            'refresh_token' => '_oauth_refresh_token',
	            'code' => '_oauth_authorization_code',
	            'jwt' => '_oauth_jwt',				
				], (array) $config['table']);
		}

	    /* ClientCredentialsInterface */
	    public function checkClientCredentials($client_id, $client_secret = null)
	    {
	        $secret = $this->_db->value("SELECT client_secret FROM `%s` WHERE client_id='%s'", $this->_table['client'], $client_id);
	        return $secret == $client_secret;
	    }

	    public function getClientDetails($client_id)
	    {
	        return $this->_db->query("SELECT * FROM `%s` WHERE client_id='%s'", $this->_table['client'], $client_id)->row('assoc');
	    }

	    public function checkRestrictedGrantType($client_id, $grant_type)
	    {
	        $details = $this->getClientDetails($client_id);
	        if (isset($details['grant_types'])) {
	            return in_array($grant_type, (array) $details['grant_types']);
	        }

	        // if grant_types are not defined, then none are restricted
	        return true;
	    }

	    /* AccessTokenInterface */
	    public function getAccessToken($access_token)
	    {
	        $query = $this->_db->query("SELECT * FROM `%s` where access_token = '%s'"
	        		, $this->_table['access_token']
	        		, $access_token);
			$token = $query->row('assoc');
			if ($token) {
				$token['expires'] = strtotime($token['expires']);
			}
	        return $token;
	    }

	    public function setAccessToken($access_token, $client_id, $user_id, $expires, $scope = null)
	    {
	        // convert expires to datestring
	        $expires = date('Y-m-d H:i:s', $expires);

	        // if it exists, update it.
	        if ($this->getAccessToken($access_token)) {
	            $SQL = "UPDATE `%s` SET client_id='%s', expires='%s', user_id='%s', scope='%s' where access_token='%s'";
	            $this->_db->query($SQL
	        		, $this->_table['access_token']
	        		, $client_id, $expires, $user_id, $scope
	        		, $access_token);
	        } else {
	        	$SQL = "INSERT INTO `%s` (access_token, client_id, expires, user_id, scope) VALUES ('%s', '%s', '%s', '%s', '%s')";
	            $this->_db->query($SQL
	        		, $this->_table['access_token']
	        		, $access_token
	        		, $client_id, $expires, $user_id, $scope);
	        }
	    }

	    /* AuthorizationCodeInterface */
	    public function getAuthorizationCode($code)
	    {
	        $query = $this->_db->query("SELECT * FROM `%s` where authorization_code = '%s'", $this->_table['code'], $code);
			$code = $query->row('assoc');
			if ($code) {
				$code['expires'] = strtotime($code['expires']);
			}
	        return $code;
	    }

	    public function setAuthorizationCode($code, $client_id, $user_id, $redirect_uri, $expires, $scope = null)
	    {
	        // convert expires to datestring
	        $expires = date('Y-m-d H:i:s', $expires);

	        // if it exists, update it.
	        if ($this->getAuthorizationCode($code)) {
	            $SQL = "UPDATE `%s` SET client_id='%s', user_id='%s', redirect_uri='%s', expires='%s', scope='%s' WHERE authorization_code='%s'";
	            $this->_db->query($SQL
	        		, $this->_table['code']
	        		, $client_id, $user_id, $redirect_uri, $expires, $scope
	        		, $code);
	        } else {
	        	$SQL = "INSERT INTO `%s` (authorization_code, client_id, user_id, redirect_uri, expires, scope) VALUES ('%s', '%s', '%s', '%s', '%s', '%s')";
	            $this->_db->query($SQL
	        		, $this->_table['code']
	        		, $code
	        		, $client_id, $user_id, $redirect_uri, $expires, $scope);
	        }
	    }

	    public function expireAuthorizationCode($code)
	    {
			$this->_db->query("DELETE FROM `%s` WHERE authorization_code='%s'"
	        		, $this->_table['code'], $code);
	    }

	    /* UserCredentialsInterface */
	    public function checkUserCredentials($username, $password)
	    {
	        if ($user = $this->getUser($username)) {
	            return $this->checkPassword($user, $password);
	        }
	        return false;
	    }

	    public function getUserDetails($username)
	    {
	        return $this->getUser($username);
	    }

	    /* RefreshTokenInterface */
	    public function getRefreshToken($refresh_token)
	    {
	    	$query = $this->_db->query("SELECT * FROM `%s` WHERE refresh_token='%s'"
	    		, $this->_table['refresh_token'], $refresh_token);
	    	$token = $query->row('assoc');
	    	if ($token) {
				$token['expires'] = strtotime($token['expires']);	    		
	    	}

	        return $token;
	    }

	    public function setRefreshToken($refresh_token, $client_id, $user_id, $expires, $scope = null)
	    {
	        // convert expires to datestring
	        $expires = date('Y-m-d H:i:s', $expires);

        	$SQL = "INSERT INTO `%s` (refresh_token, client_id, expires, user_id, scope) VALUES ('%s', '%s', '%s', '%s', '%s')";
            $this->_db->query($SQL
        		, $this->_table['refresh_token']
        		, $refresh_token
        		, $client_id, $user_id, $expires, $scope);
	    }

	    public function unsetRefreshToken($refresh_token)
	    {
			$this->_db->query("DELETE FROM `%s` WHERE refresh_token='%s'"
	        		, $this->_table['refresh_token'], $refresh_token);
	    }

	    // plaintext passwords are bad!  Override this for your application
	    protected function checkPassword($user, $password)
	    {
	    	//use interal auth to check user and password
	        $auth = new \Model\Auth($user);
	        return $auth->verify($user, $password);
	    }

	    public function getUser($username)
	    {
	    	// since we are using gini internal mechansim, we disabled setUser here
	    	// DO NOTHING!
	        return array('username'=>$username);
	    }

	    public function setUser($username, $password, $firstName = null, $lastName = null)
	    {
	    	// since we are using gini internal mechansim, we disabled setUser here
	    	// DO NOTHING!
	    }

	    public function getClientKey($client_id, $subject)
	    {
	    	return $this->_db->value("SELECT public_key FROM `%s` WHERE client_id='%s' AND subject='%s'"
	    		, $this->_table['jwt'], $client_id, $subject);
	    }

	    public function getClientScope($user_id, $client_id) {
	    	$client_scope = $this->_db->value("SELECT scope FROM `%s` WHERE user_id='%s' AND client_id='%s'"
	    		, $this->_table['client_scope'], $user_id, $client_id);
	    	return $client_scope;
	    }

	    public function setClientScope($user_id, $client_id, $scope) {
	    	$scope = $scope ?: $this->getDefaultScope();
	    	$client_scope = $this->getClientScope($user_id, $client_id);
	    	if ($client_scope) {
	    		$client_scope = array_merge(explode(' ', $client_scope), explode(' ', $scope));
	    		$client_scope = implode(' ', $client_scope);
	            $SQL = "UPDATE `%s` SET scope='%s' where user_id='%s' AND client_id='%s'";
	            $this->_db->query($SQL
	        		, $this->_table['client_scope']
	        		, $client_scope
	        		, $user_id, $client_id);
	        } else {
	        	$SQL = "INSERT INTO `%s` (user_id, client_id, scope) VALUES ('%s', '%s', '%s')";
	            $this->_db->query($SQL
	        		, $this->_table['client_scope']
	        		, $user_id, $client_id
	        		, $scope);
	        }
	    }

	    public function unsetClientScope($user_id, $client_id, $scope) {
	    	if (!$scope) return;

	    	$client_scope = $this->getClientScope($user_id, $client_id);
	    	if ($client_scope) {
	    		$client_scope = array_diff(explode(' ', $client_scope), explode(' ', $scope));
	    		if (count($client_scope) == 0) {
	    			$SQL = "DELETE FROM `%s` WHERE user_id='%s' AND client_id='%s'";
	    			$this->_db->query($SQL
	    				, $this->_table['client_scope']
	    				, $user_id, $client_id);
	    		}
	    		else {
	    			$client_scope = implode(' ', $client_scope);
		            $SQL = "UPDATE `%s` SET scope='%s' where user_id='%s' AND client_id='%s'";
		            $this->_db->query($SQL
		        		, $this->_table['client_scope']
		        		, $client_scope
		        		, $user_id, $client_id);
	    		}
	        }
	    }

	    public function getDefaultScope() {
	    	return 'default';
	    }

	    public function scopeExists($scope, $client_id = null) {
	    	return $scope == 'default';
	    }

	}

}