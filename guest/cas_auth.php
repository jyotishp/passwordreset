<?php

require_once("/usr/share/php/CAS.php");
phpCAS::client(CAS_VERSION_2_0,"login.iiit.ac.in",443,"/cas");
phpCAS::setNoCasServerValidation();
phpCAS::setExtraCurlOption(CURLOPT_SSLVERSION,1);
phpCAS::forceAuthentication();

$user = phpCAS::getUser();
$attributes = phpCAS::getUser();

$arr = split("@",$user);
$uname = $arr[0];

$invalid_user=false;

if($arr[1]=="iiit.ac.in" || $arr[1]=="students.iiit.ac.in" || $arr[1]=="research.iiit.ac.in")
{

}
else
{
        $invalid_user=true;
}


if($invalid_user)
{
        echo 'You are not allowed to access the page.';
        exit();
}

?>