<?php

// It's just a sample server controller, please override it.
namespace Gini\Controller\CGI\OAuth;

class Server extends \Gini\Controller\CGI
{
    public function actionAuth()
    {
        $form = $this->form();

        $server = \Gini\IoC::construct('\Gini\OAuth\Authorization');
        if (!$server->isValid()) {
            return false;
        }

        // check if user is logged in?
        if (!\Gini\Auth::isLoggedIn()) {
            $_SESSION['#LOGIN_REFERER'] = URL('oauth/server/auth', $this->form('get'));
            $this->redirect(\Gini\Config::get('oauth.server')['login_url']);
        }

        if ($_SERVER['REQUEST_METHOD'] == 'POST') {
            if ($form['authorize']) {
                // Generate an authorization code
                $url = $server->authorize(\Gini\Auth::userName());
            } else {
                $url = $server->deny();
            }
            $this->redirect($url);
        }

        $viewName = \Gini\Config::get('oauth.auth_view') ?: 'oauth/authorize';
        return \Gini\IoC::construct('\Gini\CGI\Response\HTML', V($viewName, [
            'form' => $form,
            'client' => $server->clientDetails()
        ]));
    }

    public function actionToken()
    {
        $server = \Gini\IoC::construct('\Gini\OAuth\Authorization');
        $response = $server->issueAccessToken();

        return \Gini\IoC::construct('\Gini\CGI\Response\JSON', $response);
    }

    public function actionUser()
    {
        $resource = \Gini\IoC::construct('\Gini\OAuth\Resource', $_GET['access_token']);
        if ($resource->isValid()) {
            $username = $resource->getUserName();
            $user = a('user', ['username'=>$username]);

            return \Gini\IoC::construct('\Gini\CGI\Response\JSON', [
                 'username' => $username,
                 'name' => $user->name,
                 'email' => $user->email,
            ]);
        }

        return false;
    }
}
