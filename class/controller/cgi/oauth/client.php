<?php

namespace Controller\CGI\OAuth {

	class Client extends \Controller\CGI {

		private $_client;

		function __pre_action($action, &$params) {
			parent::__pre_action($action, $params);

			$path = \Gini\Core::file_exists('vendor/autoload.php', 'oauth');
			require_once($path);
		}

		function action_auth() {

			$form = $this->form();

			$source = $form['source'];
			$s = (array) _CONF('oauth.client')['servers'][$source];

			$client = new \OAuth2\Client($s['client_id'], $s['client_secret']);

			$redirect_uri = URL('oauth/client/auth', ['source'=>$source]);

			if (isset($form['error'])) {
				$_SESSION['oauth.client.token'][$source] = '@'.$form['error'];
			}
			elseif (isset($form['code'])) {
				// got authorization code, try to acquire access token
				$params = ['code'=>$form['code'], 'redirect_uri'=>$redirect_uri];
				$response = $client->getAccessToken($s['token'], 'authorization_code', $params);
			    $access_token = isset($response['error']) ? null : $response['result']['access_token'];
			    $_SESSION['oauth.client.token'][$source] = $access_token ?: '@'.$response['error'];
			}
			else {
				// start oauth process...
				$_SESSION['oauth.client.redirect_uri'][$source] = $form['redirect_uri'] ?: '/';
				$url = $client->getAuthenticationUrl($s['auth'], $redirect_uri, (array)$s['extra']);
				\Model\CGI::redirect($url);
				return;
			}

			// redirect to original place
	    	$redirect_uri = $_SESSION['oauth.client.redirect_uri'][$source];
	    	unset($_SESSION['oauth.client.redirect_uri'][$source]);
	    	\Model\CGI::redirect($redirect_uri);

		}

	}

}
