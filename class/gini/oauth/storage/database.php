<?php

namespace Gini\OAuth\Storage {

    class Database 
        implements 
        \League\OAuth2\Server\Storage\ClientInterface,
        \League\OAuth2\Server\Storage\SessionInterface,
        \League\OAuth2\Server\Storage\ScopeInterface {
        
        private $_db;
        
        function __construct($name=null) {
            $this->_db = \Gini\Database::db($name);   
        }
        
        /**
         * Validate a client
         *
         * Example SQL query:
         *
         * <code>
         * # Client ID + redirect URI
         * SELECT oc.id, oc.secret, oce.redirect_uri, oc.name,
         * oc.auto_approve
         *  FROM oauth_clients LEFT JOIN oauth_client_endpoints ON oce.client_id = oc.id
         *  WHERE oc.id = :clientId AND oce.redirect_uri = :redirectUri
         *
         * # Client ID + client secret
         * SELECT oc.id, oc.secret, oc.name, oc.auto_approve FROM oauth_clients 
         * WHERE oc.id = :clientId AND oc.secret = :clientSecret
         *
         * # Client ID + client secret + redirect URI
         * SELECT oc.id, oc.secret, oce.redirect_uri, oc.name,
         * oc.auto_approve FROM oauth_clients LEFT JOIN oauth_client_endpoints 
         * ON oce.client_id = oc.id
         * WHERE oc.id = :clientId AND oc.secret = :clientSecret AND
         * oce.redirect_uri = :redirectUri
         * </code>
         *
         * Response:
         *
         * <code>
         * Array
         * (
         *     [client_id] => (string) The client ID
         *     [client secret] => (string) The client secret
         *     [redirect_uri] => (string) The redirect URI used in this request
         *     [name] => (string) The name of the client
         *     [auto_approve] => (bool) Whether the client should auto approve
         * )
         * </code>
         *
         * @param  string     $clientId     The client's ID
         * @param  string     $clientSecret The client's secret (default = "null")
         * @param  string     $redirectUri  The client's redirect URI (default = "null")
         * @param  string     $grantType    The grant type used in the request (default = "null")
         * @return bool|array               Returns false if the validation fails, array on success
         */
        public function getClient($clientId, $clientSecret = null, $redirectUri = null, $grantType = null) {
            
            $db = $this->_db;
            
            if ($clientSecret === null) {
                $st = $db->query(
                    'SELECT oc.id, oc.secret, oce.redirect_uri, oc.name, oc.auto_approve FROM _oauth_clients AS oc LEFT JOIN _oauth_client_endpoints AS oce ON oce.client_id = oc.id WHERE oc.id = :clientId AND oce.redirect_uri = :redirectUri', 
                    null, [':clientId'=>$clientId, ':redirectUri'=>$redirectUri]
                );
            }
            elseif ($redirectUri === null) {
                $st = $db->query(
                    'SELECT oc.id, oc.secret, oc.name, oc.auto_approve FROM _oauth_clients AS oc WHERE oc.id = :clientId AND oc.secret = :clientSecret', 
                    null, [':clientId'=>$clientId, ':clientSecret'=>$clientSecret]);
            }
            else {
                $st = $db->query(
                    'SELECT oc.id, oc.secret, oce.redirect_uri, oc.name, oc.auto_approve FROM _oauth_clients AS oc LEFT JOIN _oauth_client_endpoints AS oce ON oce.client_id = oc.id WHERE oc.id = :clientId AND oc.secret = :clientSecret AND oce.redirect_uri = :redirectUri', 
                    null, [':clientId'=>$clientId, ':clientSecret'=>$clientSecret, ':redirectUri'=>$redirectUri]);
            }
            
            if ($st) {
                $row = $st->row(\PDO::FETCH_ASSOC);
                return $row ?: false;
            }
            
            return false;
        }
        
        /**
         * Create a new session
         *
         * Example SQL query:
         *
         * <code>
         * INSERT INTO oauth_sessions (client_id, owner_type,  owner_id)
         *  VALUE (:clientId, :ownerType, :ownerId)
         * </code>
         *
         * @param  string $clientId  The client ID
         * @param  string $ownerType The type of the session owner (e.g. "user")
         * @param  string $ownerId   The ID of the session owner (e.g. "123")
         * @return int               The session ID
         */
        public function createSession($clientId, $ownerType, $ownerId) {
            $db = $this->_db;
            $st = $db->query('INSERT INTO _oauth_sessions (client_id, owner_type, owner_id) VALUES (:clientId, :ownerType, :ownerId)', 
                null, [':clientId'=>$clientId, ':ownerType'=>$ownerType, ':ownerId'=>$ownerId]);
            return $st ? $db->insert_id() : false;
        }

        /**
         * Delete a session
         *
         * Example SQL query:
         *
         * <code>
         * DELETE FROM oauth_sessions WHERE client_id = :clientId AND owner_type = :type AND owner_id = :typeId
         * </code>
         *
         * @param  string $clientId  The client ID
         * @param  string $ownerType The type of the session owner (e.g. "user")
         * @param  string $ownerId   The ID of the session owner (e.g. "123")
         * @return void
         */
        public function deleteSession($clientId, $ownerType, $ownerId) {
            $db = $this->_db;
            $db->query('DELETE FROM _oauth_sessions WHERE client_id=:clientId AND owner_type=:ownerType AND owner_id=:ownerId)', 
                null, [':clientId'=>$clientId, ':ownerType'=>$ownerType, ':ownerId'=>$ownerId]);
        }

        /**
         * Associate a redirect URI with a session
         *
         * Example SQL query:
         *
         * <code>
         * INSERT INTO oauth_session_redirects (session_id, redirect_uri) VALUE (:sessionId, :redirectUri)
         * </code>
         *
         * @param  int    $sessionId   The session ID
         * @param  string $redirectUri The redirect URI
         * @return void
         */
        public function associateRedirectUri($sessionId, $redirectUri) {
            $db = $this->_db;
            $db->query('INSERT INTO _oauth_session_redirects (session_id, redirect_uri) VALUES (:sessionId, :redirectUri)', 
                null, [':sessionId'=>$sessionId, ':redirectUri'=>$redirectUri]);
        }

        /**
         * Associate an access token with a session
         *
         * Example SQL query:
         *
         * <code>
         * INSERT INTO oauth_session_access_tokens (session_id, access_token, access_token_expires)
         *  VALUE (:sessionId, :accessToken, :accessTokenExpire)
         * </code>
         *
         * @param  int    $sessionId   The session ID
         * @param  string $accessToken The access token
         * @param  int    $expireTime  Unix timestamp of the access token expiry time
         * @return int                 The access token ID
         */
        public function associateAccessToken($sessionId, $accessToken, $expireTime) {
            $db = $this->_db;
            $st = $db->query('INSERT INTO _oauth_session_access_tokens (session_id, access_token, access_token_expires) VALUES (:sessionId, :accessToken, :accessTokenExpire)', 
                null, [':sessionId'=>$sessionId, ':accessToken'=>$accessToken, ':accessTokenExpire'=>$expireTime]);
            return $st ? $db->insert_id() : false;
        }

        /**
         * Associate a refresh token with a session
         *
         * Example SQL query:
         *
         * <code>
         * INSERT INTO oauth_session_refresh_tokens (session_access_token_id, refresh_token, refresh_token_expires,
         *  client_id) VALUE (:accessTokenId, :refreshToken, :expireTime, :clientId)
         * </code>
         *
         * @param  int    $accessTokenId The access token ID
         * @param  string $refreshToken  The refresh token
         * @param  int    $expireTime    Unix timestamp of the refresh token expiry time
         * @param  string $clientId      The client ID
         * @return void
         */
        public function associateRefreshToken($accessTokenId, $refreshToken, $expireTime, $clientId) {
            $db = $this->_db;
            $db->query('INSERT INTO _oauth_session_refresh_tokens (session_access_token_id, refresh_token, refresh_token_expires, client_id) VALUES (:accessTokenId, :refreshToken, :expireTime, :clientId)',
                 null, [':accessTokenId'=>$accessTokenId, ':refreshToken'=>$refreshToken, ':expireTime'=>$expireTime, ':clientId'=>$clientId]);
        }

        /**
         * Assocate an authorization code with a session
         *
         * Example SQL query:
         *
         * <code>
         * INSERT INTO oauth_session_authcodes (session_id, auth_code, auth_code_expires)
         *  VALUE (:sessionId, :authCode, :authCodeExpires)
         * </code>
         *
         * @param  int    $sessionId  The session ID
         * @param  string $authCode   The authorization code
         * @param  int    $expireTime Unix timestamp of the access token expiry time
         * @return int                The auth code ID
         */
        public function associateAuthCode($sessionId, $authCode, $expireTime) {
            $db = $this->_db;
            $st = $db->query('INSERT INTO _oauth_session_authcodes (session_id, auth_code, auth_code_expires) VALUES (:sessionId, :authCode, :authCodeExpires)', 
                null, [':sessionId'=>$sessionId, ':authCode'=>$authCode, ':authCodeExpires'=>$expireTime]);
            return $st ? $db->insert_id() : false;
        }

        /**
         * Remove an associated authorization token from a session
         *
         * Example SQL query:
         *
         * <code>
         * DELETE FROM oauth_session_authcodes WHERE session_id = :sessionId
         * </code>
         *
         * @param  int    $sessionId   The session ID
         * @return void
         */
        public function removeAuthCode($sessionId) {
            $db = $this->_db;
            $db->query('DELETE FROM _oauth_session_authcodes WHERE session_id = :sessionId',
                 null, [':sessionId'=>$sessionId]);
        }

        /**
         * Validate an authorization code
         *
         * Example SQL query:
         *
         * <code>
         * SELECT oauth_sessions.id AS session_id, osa.id AS authcode_id FROM oauth_sessions
         *  JOIN oauth_session_authcodes ON osa.`session_id` = oauth_sessions.id
         *  JOIN oauth_session_redirects ON osr.`session_id` = oauth_sessions.id WHERE
         * oauth_sessions.client_id = :clientId AND osa.`auth_code` = :authCode
         *  AND `oauth_session_authcodes`.`auth_code_expires` >= :time AND
         *  `oauth_session_redirects`.`redirect_uri` = :redirectUri
         * </code>
         *
         * Expected response:
         *
         * <code>
         * array(
         *     'session_id' =>  (int)
         *     'authcode_id'  =>  (int)
         * )
         * </code>
         *
         * @param  string     $clientId    The client ID
         * @param  string     $redirectUri The redirect URI
         * @param  string     $authCode    The authorization code
         * @return array|bool              False if invalid or array as above
         */
        public function validateAuthCode($clientId, $redirectUri, $authCode) {
            $db = $this->_db;
            $st = $db->query('SELECT os.id AS session_id, osa.id AS authcode_id FROM _oauth_sessions AS os JOIN _oauth_session_authcodes AS osa ON osa.session_id = os.id JOIN _oauth_session_redirects AS osr ON osr.session_id = os.id WHERE os.client_id = :clientId AND osa.auth_code = :authCode AND osa.auth_code_expires >= UNIX_TIMESTAMP(NOW()) AND osr.redirect_uri = :redirectUri',
                 null, [':clientId'=>$clientId, ':redirectUri'=>$redirectUri, ':authCode'=>$authCode]
             );

             if ($st) {
                 return $st->row(\PDO::FETCH_ASSOC);
             }

             return false;
        }

        /**
         * Validate an access token
         *
         * Example SQL query:
         *
         * <code>
         * SELECT session_id, oauth_sessions.`client_id`, oauth_sessions.`owner_id`, oauth_sessions.`owner_type`
         *  FROM `oauth_session_access_tokens` JOIN oauth_sessions ON oauth_sessions.`id` = session_id WHERE
         *  access_token = :accessToken AND access_token_expires >= UNIX_TIMESTAMP(NOW())
         * </code>
         *
         * Expected response:
         *
         * <code>
         * array(
         *     'session_id' =>  (int),
         *     'client_id'  =>  (string),
         *     'owner_id'   =>  (string),
         *     'owner_type' =>  (string)
         * )
         * </code>
         *
         * @param  string     $accessToken The access token
         * @return array|bool              False if invalid or an array as above
         */
        public function validateAccessToken($accessToken) {
            $db = $this->_db;
            $st = $db->query('SELECT osat.session_id, os.client_id, os.owner_id, os.owner_type FROM _oauth_session_access_tokens AS osat JOIN _oauth_sessions AS os ON os.id = osat.session_id WHERE osat.access_token = :accessToken AND osat.access_token_expires >= UNIX_TIMESTAMP(NOW())',
                 null, [':accessToken'=>$accessToken]
             );

             if ($st) {
                 return $st->row(\PDO::FETCH_ASSOC);
             }

             return false;
        }

        /**
         * Removes a refresh token
         *
         * Example SQL query:
         *
         * <code>
         * DELETE FROM `oauth_session_refresh_tokens` WHERE refresh_token = :refreshToken
         * </code>
         *
         * @param  string $refreshToken The refresh token to be removed
         * @return void
         */
        public function removeRefreshToken($refreshToken) {
            $db = $this->_db;
            $db->query('DELETE FROM _oauth_session_refresh_tokens WHERE refresh_token = :refreshToken',
                 null, [':refreshToken'=>$refreshToken]);
        }

        /**
         * Validate a refresh token
         *
         * Example SQL query:
         *
         * <code>
         * SELECT session_access_token_id FROM `oauth_session_refresh_tokens` WHERE refresh_token = :refreshToken
         *  AND refresh_token_expires >= UNIX_TIMESTAMP(NOW()) AND client_id = :clientId
         * </code>
         *
         * @param  string   $refreshToken The access token
         * @param  string   $clientId     The client ID
         * @return int|bool               The ID of the access token the refresh token is linked to (or false if invalid)
         */
        public function validateRefreshToken($refreshToken, $clientId) {
            $db = $this->_db;
            $st = $db->query('SELECT session_access_token_id FROM _oauth_session_refresh_tokens WHERE refresh_token = :refreshToken AND refresh_token_expires >= UNIX_TIMESTAMP(NOW()) AND client_id = :clientId', 
                null, [':refreshToken'=>$refreshToken, ':clientId'=>$clientId]);
            return $st ? $st->value() : false;
        }

        /**
         * Get an access token by ID
         *
         * Example SQL query:
         *
         * <code>
         * SELECT * FROM `oauth_session_access_tokens` WHERE `id` = :accessTokenId
         * </code>
         *
         * Expected response:
         *
         * <code>
         * array(
         *     'id' =>  (int),
         *     'session_id' =>  (int),
         *     'access_token'   =>  (string),
         *     'access_token_expires'   =>  (int)
         * )
         * </code>
         *
         * @param  int    $accessTokenId The access token ID
         * @return array
         */
        public function getAccessToken($accessTokenId) {
            $db = $this->_db;
            $st = $db->query('SELECT * FROM _oauth_session_access_tokens WHERE id = :accessTokenId',
                 null, [':accessTokenId'=>$accessTokenId]
             );

             if ($st) {
                 return $st->row(\PDO::FETCH_ASSOC);
             }

             return false;
         }

        /**
         * Associate scopes with an auth code (bound to the session)
         *
         * Example SQL query:
         *
         * <code>
         * INSERT INTO `oauth_session_authcode_scopes` (`oauth_session_authcode_id`, `scope_id`) VALUES
         *  (:authCodeId, :scopeId)
         * </code>
         *
         * @param  int $authCodeId The auth code ID
         * @param  int $scopeId    The scope ID
         * @return void
         */
        public function associateAuthCodeScope($authCodeId, $scopeId) {
            $db = $this->_db;
            $db->query('INSERT INTO _oauth_session_authcode_scopes (oauth_session_authcode_id, scope_id) VALUES (:authCodeId, :scopeId)',
                 null, [':authCodeId'=>$authCodeId, ':scopeId'=>$scopeId]
             );
        }

        /**
         * Get the scopes associated with an auth code
         *
         * Example SQL query:
         *
         * <code>
         * SELECT scope_id FROM `oauth_session_authcode_scopes` WHERE oauth_session_authcode_id = :authCodeId
         * </code>
         *
         * Expected response:
         *
         * <code>
         * array(
         *     array(
         *         'scope_id' => (int)
         *     ),
         *     array(
         *         'scope_id' => (int)
         *     ),
         *     ...
         * )
         * </code>
         *
         * @param  int   $oauthSessionAuthCodeId The session ID
         * @return array
         */
        public function getAuthCodeScopes($oauthSessionAuthCodeId) {
            $db = $this->_db;
            $st = $db->query('SELECT scope_id FROM _oauth_session_authcode_scopes WHERE oauth_session_authcode_id = :authCodeId',
                 null, [':authCodeId'=>$oauthSessionAuthCodeId]
             );

             return $st ? $st->rows(\PDO::FETCH_ASSOC) : [];
        }

        /**
         * Associate a scope with an access token
         *
         * Example SQL query:
         *
         * <code>
         * INSERT INTO `oauth_session_token_scopes` (`session_access_token_id`, `scope_id`) VALUE (:accessTokenId, :scopeId)
         * </code>
         *
         * @param  int    $accessTokenId The ID of the access token
         * @param  int    $scopeId       The ID of the scope
         * @return void
         */
        public function associateScope($accessTokenId, $scopeId) {
            $db = $this->_db;
            $db->query('INSERT INTO _oauth_session_token_scopes (session_access_token_id, scope_id) VALUE (:accessTokenId, :scopeId)',
                 null, [':accessTokenId'=>$accessTokenId, ':scopeId'=>$scopeId]
             );
        }

        /**
         * Get all associated access tokens for an access token
         *
         * Example SQL query:
         *
         * <code>
         * SELECT oauth_scopes.* FROM oauth_session_token_scopes JOIN oauth_session_access_tokens
         *  ON oauth_session_access_tokens.`id` = `oauth_session_token_scopes`.`session_access_token_id`
         *  JOIN oauth_scopes ON oauth_scopes.id = `oauth_session_token_scopes`.`scope_id`
         *  WHERE access_token = :accessToken
         * </code>
         *
         * Expected response:
         *
         * <code>
         * array (
         *     array(
         *         'id'     =>  (int),
         *         'scope'  =>  (string),
         *         'name'   =>  (string),
         *         'description'    =>  (string)
         *     ),
         *     ...
         *     ...
         * )
         * </code>
         *
         * @param  string $accessToken The access token
         * @return array
         */
        public function getScopes($accessToken) {
            $db = $this->_db;
            $st = $db->query('SELECT os.* FROM _oauth_session_token_scopes AS osts JOIN _oauth_session_access_tokens AS osat ON osat.id = osts.session_access_token_id JOIN _oauth_scopes AS os ON os.id = osts.scope_id WHERE osat.access_token = :accessToken',
                 null, [':accessToken'=>$accessToken]
             );

             return $st ? $st->rows(\PDO::FETCH_ASSOC) : [];
        }

        /**
         * Return information about a scope
         *
         * Example SQL query:
         *
         * <code>
         * SELECT * FROM oauth_scopes WHERE scope = :scope
         * </code>
         *
         * Response:
         *
         * <code>
         * Array
         * (
         *     [id] => (int) The scope's ID
         *     [scope] => (string) The scope itself
         *     [name] => (string) The scope's name
         *     [description] => (string) The scope's description
         * )
         * </code>
         *
         * @param  string     $scope     The scope
         * @param  string     $clientId  The client ID (default = "null")
         * @param  string     $grantType The grant type used in the request (default = "null")
         * @return bool|array If the scope doesn't exist return false
         */
        public function getScope($scope, $clientId = null, $grantType = null) {
            $db = $this->_db;
            $st = $db->query('SELECT * FROM _oauth_scopes WHERE scope = :scope',
                 null, [':scope'=>$scope]
             );

             return $st ? $st->row(\PDO::FETCH_ASSOC) : false;
        }

    }
    
}