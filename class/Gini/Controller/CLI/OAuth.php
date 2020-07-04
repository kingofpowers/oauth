<?php

namespace Gini\Controller\CLI {

    class OAuth extends \Gini\Controller\CLI
    {
        public function actionPrepare($args)
        {
            $path = \Gini\Core::locateFile(RAW_DIR . '/oauth/mysql.sql', 'oauth');
            if (file_exists($path)) {
                $db = \Gini\Database::db();
                $SQL = file_get_contents($path);
                $db->exec($SQL);
            }
        }
    }
}
