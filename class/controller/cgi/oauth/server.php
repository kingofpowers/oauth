<?php

namespace Controller\CGI\OAuth {

	class Server extends \Controller\CGI\Layout {

//		protected static $layout_name = 'phtml/oauth/layout';

		private $_server;
		private $_storage;

		function __pre_action($action, &$params) {
			parent::__pre_action($action, $params);

			$path = \Gini\Core::file_exists('vendor/autoload.php', 'oauth');
			require_once($path);

			$this->_storage = new \Model\OAuth\Storage\Database();
			$this->_server = new \OAuth2_Server($this->_storage);
		}

		function action_auth() {

			$this->_server->addGrantType(new \OAuth2_GrantType_ClientCredentials($this->_storage));

			$response = new \OAuth2_Response();
			$request = \OAuth2_Request::createFromGlobals();
			if (!$this->_server->validateAuthorizeRequest($request, $response)) {
				$response->send();
				return FALSE;
			}

			// check if user is logged in?
			if (!\Model\Auth::logged_in()) {
			    $_SESSION['#LOGIN_REFERER'] = URL('oauth/server/auth', $this->form()['get']);
				\Model\CGI::redirect(_CONF('oauth.server')['login_url']);
			}

			$user_id = \Model\Auth::username();
			$client_id = $request->query('client_id');

			if ($_SERVER['REQUEST_METHOD'] == 'POST') {
				if ($request->request('authorize')) {
					$this->_storage->setClientScope($user_id, $client_id, $request->request('scope'));
				}
				else {
					$this->_server->handleAuthorizeRequest($request, $response, FALSE, $user_id)->send();
					return FALSE;
				}
			}

			// check if is authorized
			$scope = $this->_storage->getClientScope($user_id, $client_id);
			if ($scope !== null) {
				$this->_server->handleAuthorizeRequest($request, $response, TRUE, $user_id)->send();
				return FALSE;
			}

			$client = $this->_storage->getClientDetails($client_id);

			$this->view->body = V('phtml/oauth/authorize', array('request'=>$request, 'client'=>$client));
		}

		function action_token() {

			$this->_server->addGrantType(new \OAuth2_GrantType_AuthorizationCode($this->_storage));
			$this->_server->addGrantType(new \OAuth2_GrantType_RefreshToken($this->_storage));
			
			// Handle a request for an OAuth2.0 Access Token and send the response to the client
			$this->_server->handleTokenRequest(\OAuth2_Request::createFromGlobals(), new \OAuth2_Response(), TRUE)->send();
			return FALSE;
		}

	}

}
