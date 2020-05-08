# OAuth 认证模块

## RELEASE LOG

- 2020.05.08 升级到 0.4.x

  1. 获取`accessToken`增加了内部认证方式 `internal`.
     ```php
     $server = new \Gini\OAuth\Authorization();
     $server->issueAccessToken(
         [
             'grant_type' => 'internal',
             'client_id' => '你的clientId',
             'owner_type' => '资源Owner类型',
             'owner_id' => '资源Owner ID',
             'scope' => '应用范围(可选)'
         ],
         true // 这是额外增加的一个参数, internal方法只有在这个参数为true的时候才可用, 避免外界意外传入不安全的参数绕过认证
     )
     ```
  2. 将依赖的 `league/oauth-client` 升级到 2.x

     > 由于 `league/oauth-client` 修改了实现, 用 `ResourceOwner` 的概念取消掉了之前 `User` 的概念，同时 `AccessToken` 封闭了内部数据属性，新的 `\Gini\OAuth\Client`的调用产生了变化。

     ```php
     $client = new \Gini\OAuth\Client('gini');
     $token = $client->fetchAccessToken();
     // $token->accessToken, $token->expires 无法访问
     $accessToken = (string) $token;
     $accessToken = $token->getToken();
     $refreshToken = $token->getRefreshToken();
     $expires = $token->getExpires();

     // 增加了是否超期的直接判断
     if ($token->hasExpired()) {
         // refresh
     }
     ```
