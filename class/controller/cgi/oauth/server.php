<?php

// It's just a sample server controller, please override it.

namespace Controller\CGI\OAuth {

    class Server extends \Controller\CGI {

        function action_auth() {

            $form = $this->form();
            
            $server = new \Model\OAuth\Authorization;
            
            if (!$server->isValid()) return false;

            // check if user is logged in?
            if (!\Model\Auth::logged_in()) {
                $_SESSION['#LOGIN_REFERER'] = URL('oauth/server/auth', $this->form('get'));
                \Model\CGI::redirect(_CONF('oauth.server')['login_url']);
            }

            if ($_SERVER['REQUEST_METHOD'] == 'POST') {
                if ($form['authorize']) {
                    // Generate an authorization code
                    $url = $server->authorize(\Model\Auth::username());
                }
                else {
                    $url = $server->deny();
                }
                \Model\CGI::redirect($url); 
            }

            return new \Model\CGI\Response\HTML(V('phtml/oauth/authorize', [
                'form' => $form,
                'client' => $server->clientDetails()
            ]));
        }

        function action_token() {
            $server = new \Model\OAuth\Authorization;
            $response = $server->issueAccessToken();
            return new \Model\CGI\Response\JSON($response);
        }

        function action_user() {
            $resource = new \Model\OAuth\Resource($_GET['access_token']);
            if ($resource->isValid()) {
                $username = $resource->getUserName();
                $user = a('user', ['username'=>$username]);
                return new \Model\CGI\Response\JSON([
                     'username' => $username,
                     'name' => $user->name,
                     'email' => $user->email,
                ]);
            }
            return false;
        }
        
    }

}
