<?php

// It's just a sample server controller, please override it.

namespace Controller\CGI\OAuth {

    class Server extends \Controller\CGI {

        function action_auth() {

            $form = $this->form();
            
            $server = new \Gini\OAuth\Authorization;
            
            if (!$server->isValid()) return false;

            // check if user is logged in?
            if (!\Gini\Auth::logged_in()) {
                $_SESSION['#LOGIN_REFERER'] = URL('oauth/server/auth', $this->form('get'));
                $this->redirect(_CONF('oauth.server')['login_url']);
            }

            if ($_SERVER['REQUEST_METHOD'] == 'POST') {
                if ($form['authorize']) {
                    // Generate an authorization code
                    $url = $server->authorize(\Gini\Auth::username());
                }
                else {
                    $url = $server->deny();
                }
                $this->redirect($url); 
            }

            return new \Gini\CGI\Response\HTML(V('phtml/oauth/authorize', [
                'form' => $form,
                'client' => $server->clientDetails()
            ]));
        }

        function action_token() {
            $server = new \Gini\OAuth\Authorization;
            $response = $server->issueAccessToken();
            return new \Gini\CGI\Response\JSON($response);
        }

        function action_user() {
            $resource = new \Gini\OAuth\Resource($_GET['access_token']);
            if ($resource->isValid()) {
                $username = $resource->getUserName();
                $user = a('user', ['username'=>$username]);
                return new \Gini\CGI\Response\JSON([
                     'username' => $username,
                     'name' => $user->name,
                     'email' => $user->email,
                ]);
            }
            return false;
        }
        
    }

}
