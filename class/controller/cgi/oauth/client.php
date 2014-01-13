<?php

namespace Controller\CGI\OAuth {

	class Client extends \Controller\CGI {

		private $_client;

		function action_auth() {

			$form = $this->form();

			$source = $form['source'];
            $client = new \Gini\OAuth\Client($source);
            
			if (isset($form['error'])) {
				$_SESSION['oauth.client.token'][$source] = '@'.$form['error'];
			}
			elseif (isset($form['code'])) {
				// got authorization code, try to acquire access token
                $client->fetchAccessToken('authorization_code', ['code'=>$form['code']]);
			}
			else {
				// start oauth process...
				$_SESSION['oauth.client.redirect_uri'][$source] = $form['redirect_uri'] ?: '/';
                $client->authorize();
                return;
			}

			// redirect to original place
	    	$redirect_uri = $_SESSION['oauth.client.redirect_uri'][$source];
	    	unset($_SESSION['oauth.client.redirect_uri'][$source]);
	    	$this->redirect($redirect_uri);
		}

	}

}
