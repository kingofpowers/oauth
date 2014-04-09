<?php

namespace Gini\Module;

class OAuth
{
    public static function setup()
    {
        $composer_path = \Gini\Core::locateFile('vendor/autoload.php', 'oauth');
        if ($composer_path) require_once $composer_path;
    }

}
