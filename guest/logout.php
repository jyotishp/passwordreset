<?php
session_destroy();
require_once('cas_auth.php');
phpCAS::logout();
exit();
?>