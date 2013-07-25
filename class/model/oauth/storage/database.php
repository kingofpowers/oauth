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

		function __construct($connection=null, $config = array()) {
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
	        $secret = $this->_db->value('SELECT "client_secret" FROM :table WHERE "client_id"=:id', 
                            [':table'=>$this->_table['client']], [':id'=>$client_id]);
	        return $secret == $client_secret;
	    }

	    public function getClientDetails($client_id)
	    {
            $st = $this->_db->query('SELECT * FROM :table WHERE "client_id"=:id', 
                                    [':table'=>$this->table['client']], [':id'=>$client_id]);
	        return $st ? $st->row('assoc') : [];
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
	        $query = $this->_db->query('SELECT * FROM :table where "access_token" = :token',
                        [':table'=>$this->_table['access_token']],
	        		    [':token'=>$access_token]);
			$token = $query ? $query->row('assoc') : null;
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
	            $this->_db->query('UPDATE :table SET "client_id"=:client_id, "expires"=:expires, "user_id"=:user_id, "scope"=:scope where "access_token"=:token',
	        		[':table'=>$this->_table['access_token']],
	        		[
                        ':client_id'=>$client_id, 
                        ':expires'=>$expires, 
                        ':user_id'=>$user_id, 
                        ':scope'=>$scope,
	        		    ':token'=>$access_token
                    ]);
	        } else {
	        	$SQL = '';
	            $this->_db->query('INSERT INTO :table ("access_token", "client_id", "expires", "user_id", "scope") VALUES (:token, :client_id, :expires, :user_id, :scope)', 
                    [':table'=>$this->_table['access_token']],
	        		[
                        ':client_id'=>$client_id, 
                        ':expires'=>$expires, 
                        ':user_id'=>$user_id, 
                        ':scope'=>$scope,
	        		    ':token'=>$access_token
                    ]);
	        }
	    }

	    /* AuthorizationCodeInterface */
	    public function getAuthorizationCode($code)
	    {
	        $query = $this->_db->query('SELECT * FROM :table WHERE "authorization_code" = :code', 
                        [':table'=>$this->_table['code']], 
                        [':code'=>$code]);
			$code = $query ? $query->row('assoc') : null;
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
	            $this->_db->query('UPDATE :table SET "client_id"=:client_id, "user_id"=:user_id, 
                                        "redirect_uri"=:uri, "expires"=:expires, "scope"=:scope 
                                        WHERE "authorization_code"=:code', 
                                [':table'=>$this->_table['code']],
                                [
                                    ':client_id'=>$client_id, 
                                    ':user_id'=>$user_id, 
                                    ':uri'=>$redirect_uri, 
                                    ':expires'=>$expires, 
                                    ':scope'=>$scope, 
                                    ':code'=>$code
                                ]);
	        } else {
	        	$SQL = "";
	            $this->_db->query('INSERT INTO :table ("authorization_code", "client_id", "user_id", "redirect_uri", "expires", "scope") VALUES (:code, :client_id :user_id, :uri, :expires, :scope)',
	        		 [':table'=>$this->_table['code']],
                     [
                         ':client_id'=>$client_id, 
                         ':user_id'=>$user_id, 
                         ':uri'=>$redirect_uri, 
                         ':expires'=>$expires, 
                         ':scope'=>$scope, 
                         ':code'=>$code
                     ]);
	        }
	    }

	    public function expireAuthorizationCode($code)
	    {
			$this->_db->query('DELETE FROM :table WHERE "authorization_code"=:code',
                            [':table'=>$this->_table['code']], 
                            [':code'=>$code]);
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
	    	$query = $this->_db->query('SELECT * FROM :table WHERE "refresh_token"=:token',
                                    [':table'=>$this->_table['refresh_token']], 
                                    [':token'=>$refresh_token]);
	    	$token = $query ? $query->row('assoc') : null;
	    	if ($token) {
				$token['expires'] = strtotime($token['expires']);	    		
	    	}

	        return $token;
	    }

	    public function setRefreshToken($refresh_token, $client_id, $user_id, $expires, $scope = null)
	    {
	        // convert expires to datestring
	        $expires = date('Y-m-d H:i:s', $expires);

            $this->_db->query('INSERT INTO :table ("refresh_token", "client_id", "expires", "user_id", "scope") 
                                VALUES (:token, :client_id, :expires, :user_id, :scope)',
                                [':table'=>$this->_table['refresh_token']],
                                [
                                    ':token'=>$refresh_token, 
                                    ':client_id'=>$client_id, 
                                    ':user_id'=>$user_id, 
                                    ':expires'=>$expires, 
                                    ':scope'=>$scope
                                ]);
	    }

	    public function unsetRefreshToken($refresh_token)
	    {
			$this->_db->query('DELETE FROM :table WHERE "refresh_token"=:token',
	        		    [':table'=>$this->_table['refresh_token']], 
                        [':token'=>$refresh_token]);
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
	    	return $this->_db->value('SELECT "public_key" FROM :table WHERE "client_id"=:client_id AND "subject"=:subject',
                                [':table'=>$this->_table['jwt']], 
                                [':client_id'=>$client_id, ':subject'=>$subject]);
	    }

	    public function getClientScope($user_id, $client_id) {
	    	$client_scope = $this->_db->value('SELECT "scope" FROM :table WHERE "user_id"=:user_id AND "client_id"=:client_id',
                                            [':table'=>$this->_table['client_scope']],
                                            [':user_id'=>$user_id, ':client_id'=>$client_id]);
	    	return $client_scope;
	    }

	    public function setClientScope($user_id, $client_id, $scope) {
	    	$scope = $scope ?: $this->getDefaultScope();
	    	$client_scope = $this->getClientScope($user_id, $client_id);
	    	if ($client_scope) {
	    		$client_scope = array_merge(explode(' ', $client_scope), explode(' ', $scope));
	    		$client_scope = implode(' ', $client_scope);
	            $this->_db->query('UPDATE :table SET "scope"=:scope WHERE "user_id"=:user_id AND "client_id"=:client_id',
                                [':table'=>$this->_table['client_scope']],
                                [
                                    ':scope'=>$client_scope,
	        		                ':user_id'=>$user_id, 
                                    ':client_id'=>$client_id
                                ]);
	        } else {
	            $this->_db->query('INSERT INTO :table ("user_id", "client_id", "scope") VALUES ('%s', '%s', '%s')',
                                [':table'=>$this->_table['client_scope']],
                                [
                                    ':user_id'=>$user_id, 
                                    ':client_id'=>$client_id,
                                    ':scope'=>$scope
                                ]);
	        }
	    }

	    public function unsetClientScope($user_id, $client_id, $scope) {
	    	if (!$scope) return;

	    	$client_scope = $this->getClientScope($user_id, $client_id);
	    	if ($client_scope) {
	    		$client_scope = array_diff(explode(' ', $client_scope), explode(' ', $scope));
	    		if (count($client_scope) == 0) {
	    			$this->_db->query('DELETE FROM :table WHERE "user_id"=:user_id AND "client_id"=:client_id',
                                    [':table'=>$this->_table['client_scope']],
                                    [':user_id'=>$user_id, ':client_id'=>$client_id]);
	    		}
	    		else {
	    			$client_scope = implode(' ', $client_scope);
		            $this->_db->query('UPDATE :table SET "scope"=:scope WHERE "user_id"=:user_id AND "client_id"=:client_id',
                                    [':table'=>$this->_table['client_scope']],
                                    [
                                        ':scope'=>$client_scope, 
                                        ':user_id'=>$user_id, 
                                        ':client_id'=>$client_id
                                    ]);
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