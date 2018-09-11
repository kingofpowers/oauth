<?php

namespace Gini\OAuth\Client {

    use \League\OAuth2\Client\Provider\AbstractProvider;
    use \League\OAuth2\Client\Entity\User;
    use \League\OAuth2\Client\Token\AccessToken;

    class Gini extends AbstractProvider
    {
        public $scopes = ['user'];
        public $responseType = 'json';
        public $options = [];

        public function urlAuthorize()
        {
            return $this->options['auth'];
        }

        public function urlAccessToken()
        {
            return $this->options['token'];
        }

        public function urlUserDetails(AccessToken $token)
        {
            return URL($this->options['user'], ['access_token'=>(string) $token]);
        }

        public function userDetails($response, AccessToken $token)
        {
            $user = new User;
            $user->name = $response->name;
            $user->email = $response->email;
            $user->uid = $response->id;
            return $user;
        }

        public function userUid($response, AccessToken $token)
        {
            return $response->username;
        }

        public function userEmail($response, AccessToken $token)
        {
            return isset($response->email) && $response->email ? $response->email : null;
        }

        public function userScreenName($response, AccessToken $token)
        {
            return $response->name;
        }
    }

}
