<?php

$allowed_ips=array('127.0.0.1');
if (!in_array($_SERVER['REMOTE_ADDR'], $allowed_ips)) {
	echo "Sorry, access denied!";
	exit(0);
}

function valid_user($email, $password)
{
  $base_dn = "ou=Users,dc=iiit,dc=ac,dc=in";
  $filter = '(mail='.$email.')';

  $ds = ldap_connect("ldap.iiit.ac.in", 389) or die("Could not connect to $ldaphost");
  $opt = ldap_set_option($ds, LDAP_OPT_PROTOCOL_VERSION, 3);
  $tls = ldap_start_tls($ds);
  $anon_bind = ldap_bind($ds);
  if ($ds and $opt and $tls) {
    $search = ldap_search($ds, $base_dn, $filter);
    $first_entry = ldap_first_entry($ds, $search);
    $dn = ldap_get_dn($ds, $first_entry);
    $bind_result = ldap_bind($ds, $dn, $password);
  } else {
    $bind_result = false;
  }

  ldap_close($ds);
  return $bind_result and valid_email($dn);
}

function valid_email($dn)
{
  if (strpos($dn, "ou=Research,ou=Users,dc=iiit,dc=ac,dc=in") !== false or // remove this
      strpos($dn, "ou=Staff,ou=Mail,ou=Users,dc=iiit,dc=ac,dc=in") !== false or
      strpos($dn, "ou=Faculty,ou=Mail,ou=Users,dc=iiit,dc=ac,dc=in") !== false) return true;
  // add L1 access
  return false;
}

function generateSambaNTPassword($pass){
// https://www.jotschi.de/Uncategorized/2010/08/10/howto-generate-sambantpassword-ldap-attribute.html
  return strtoupper(
      bin2hex(
        hash("md4",
          iconv(
            "UTF-8","UTF-16LE",$pass
            ), true
          )
        )
    );
}

function add_ldap_entry($email,
                        $password,
                        $first_name,
                        $last_name,
                        $guest_mail,
                        $phone)
{
  if (valid_user($email, $password)) {
  	$tmp_password = 'iiit@' . rand(1000,100000);
    $hashed_password = generateSambaNTPassword($tmp_password);

    $base_dn = "ou=Users,dc=iiit,dc=ac,dc=in";
    $filter = '(mail='.$email.')';

    $info["cn"] = "John Jones";
    $info["sn"] = "Jones";
    $info["objectclass"] = "person";

    $uid = explode('@', $guest_mail)[0];
    $guest_dn = "uid=" . $uid . ",ou=Guest,ou=Users,dc=iiit,dc=ac,dc=in";
    $person = [
        'cn' => $first_name . ' ' . $last_name,
        'sn' => $last_name,
        'givenName' => $first_name,
        'telephoneNumber' => $phone,
        'mail' => $guest_mail,
        'sambaSID' => $phone,
        'sambaNTPassword' => $hashed_password,
        'objectclass' => ['organizationalPerson', 'top', 'inetOrgPerson', 'person', 'SambaSamAccount', 'inetUser'],
        'description' => 'Added on ' . date("F j, Y, g:i a") . ' by ' . $email . '.',
      ];

    $ds = ldap_connect("ldap.iiit.ac.in", 389) or die("Could not connect to $ldaphost");
    $opt = ldap_set_option($ds, LDAP_OPT_PROTOCOL_VERSION, 3);
    $tls = ldap_start_tls($ds);

    global $adminDN, $adminPass;

    $bind_result = ldap_bind($ds, $adminDN, $adminPass);
    if ($bind_result == false) {
      return false;
    }

    $ldap_add_result = ldap_add($ds, $guest_dn, $person);
    if ($ldap_add_result) {
      $guest_message = "Dear $first_name $last_name,

      Your 802.1x credentials to access IIIT-H network are:
      username: $guest_mail
      password: $tmp_password

      Please do not share your credentials with anyone. You are receiving this email because we received a request from $email to give you access to our network.

      Regards
      Systems Administrators
      IIIT Hyderabad";

      $iiit_user_message = "Dear User

      We have generated and mailed 802.1x credentials for $guest_mail as per your request.

      Regards
      Systems Administrators
      IIIT Hyderabad";
      mail ( $guest_mail , "Credentials to access IIIT-H network", $guest_message);
      mail ( $email, "Created guest credentials", $iiit_user_message );

      return true;
    }
  }
}
