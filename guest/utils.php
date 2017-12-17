<?php
/*
 * @author: Jyotish P <srisai.poonganam@research.iiit.ac.in>
 */

/*
 * Open the log file
 */
openlog("Guest Credentials
", LOG_PID, LOG_LOCAL0);

/*
 * This function logs the $message to syslog
 * $requestID for having unique entries
 */
$requestID = md5(uniqid(rand(), true));
function logToSyslog($message) {
	global $requestID;
	syslog(LOG_INFO, "$requestID : $message");
}

/*
 * Check if the user entered the correct IIIT credentials
 * $email = IIIT user's E-Mail
 * $password = plain text password
 */
function valid_user($email, $password)
{
	$base_dn = "dc=iiit,dc=ac,dc=in";
	$filter = '(mail='.$email.')';

	# Connection parameters
	$ds = ldap_connect("ldap.iiit.ac.in", 389) or die("Could not connect to $ldaphost");
	$opt = ldap_set_option($ds, LDAP_OPT_PROTOCOL_VERSION, 3);
	$tls = ldap_start_tls($ds);
	$anon_bind = ldap_bind($ds);

	# Search only if all options are enabled
	if ($ds and $opt and $tls) {
		$search = ldap_search($ds, $base_dn, $filter);
		$first_entry = ldap_first_entry($ds, $search);
		$dn = ldap_get_dn($ds, $first_entry);
		$bind_result = ldap_bind($ds, $dn, $password);
	} else {
		$bind_result = false;
	}

	# Close the ldap connection
	ldap_close($ds);
	return $bind_result and valid_email($dn);
}

/*
 * Check if the user belongs to ou=Staff or ou=Faculty
 * Check if the user belongs to L1 access group
 */
function valid_email($dn)
{
	# Check for ou=Staff or ou=Faculty
	if (strpos($dn, "ou=Staff,ou=Mail,ou=Users,dc=iiit,dc=ac,dc=in") !== false or
		strpos($dn, "ou=Faculty,ou=Mail,ou=Users,dc=iiit,dc=ac,dc=in") !== false) return true;

	# Check for L1 access
	if (checkGroup($dn, "cn=L1,ou=Sysadmins,ou=Groups,dc=iiit,dc=ac,dc=in"))
	// if (checkGroupEx($ds, $userdn, "cn=L1,ou=Sysadmins,ou=Groups,dc=iiit,dc=ac,dc=in")) {
		return true;
	return false;
}

/*
 * Check if the user belongs to L1 access group
 * Built in php_ldap functions need memberOf attribute on each LDAP entry
 * that belongs to the group. We don't have it that way (But why don't we?)
 * So had to retrieve all users in the group and veriy if user's in the result
 */
function checkGroup($userdn, $groupdn)
{
	$ds = ldap_connect("ldap.iiit.ac.in", 389) or die("Could not connect to $ldaphost");
	$opt = ldap_set_option($ds, LDAP_OPT_PROTOCOL_VERSION, 3);
	$tls = ldap_start_tls($ds);
	$anon_bind = ldap_bind($ds);

	if ($ds and $opt and $tls) {
		$search = ldap_search($ds, $groupdn, '(uniqueMember=*)');
		$result = ldap_get_entries($ds, $search);
		# Have to check if it works on all versions
		if (in_array($userdn, $result[0]['uniquemember']))
			return true;
	}
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

/*
 * Add Guest credentials to LDAP
 */
function add_ldap_entry($email,
						$password,
						$first_name,
						$last_name,
						$guest_mail,
						$phone,
						$expiry_time,
						$host)
{
	if (valid_user($email, $password)) {
		global $requestID, $adminDN, $adminPass;;
		logToSyslog("Requested by $email for $guest_mail (Host: $host)");

		# Generate password that should be mailed to Guest E-Mail address
		$tmp_password = substr(md5(openssl_random_pseudo_bytes(8)), 0, 8);
		$hashed_password = generateSambaNTPassword($tmp_password);

		$base_dn = "ou=Users,dc=iiit,dc=ac,dc=in";
		$filter = '(mail='.$email.')';
		date_default_timezone_set('Asia/Kolkata');

		// $uid = explode('@', $guest_mail)[0];
		# Using uniqid() to avoid uid clashes but looks like an overkill
		$uid = uniqid();
		$guest_dn = "uid=" . $uid . ",ou=Guest,ou=Users,dc=iiit,dc=ac,dc=in";
		$person = [
				'cn' => $first_name . ' ' . $last_name,
				'sn' => $last_name,
				'givenName' => $first_name,
				'telephoneNumber' => $phone,
				'mail' => $guest_mail,
				# sambaSID will be used for keeping track of expiry time
				# Adding custom fields like passwordExpiry or accountExpiry throw error
				'sambaSID' => strtotime(date("Y-m-d H:i:s")) + $expiry_time * 3600,
				'sambaNTPassword' => $hashed_password,
				'objectclass' => ['organizationalPerson', 'top', 'inetOrgPerson', 'person', 'SambaSamAccount', 'inetUser'],
				'description' => 'Added on ' . date("F j, Y, g:i a") . ' by ' . $email . '(Host: '. $host .').',
			];

		# Try connecting to LDAP server
		$ds = ldap_connect("ldap.iiit.ac.in", 389) or logToSyslog("Could not connect to ldap server", 10);
		$opt = ldap_set_option($ds, LDAP_OPT_PROTOCOL_VERSION, 3) or logToSyslog("Could not set LDAP v3", 10);
		$tls = ldap_start_tls($ds) or logToSyslog("Could not set TLS", 10);

		# Do not create credentials if options fail
		if (!$ds and !$opt and !$tls) {
			return [
				'result' => false,
				'message' => "Failed to connect to LDAP server"
				];
		}

		# Bind using admin DN
		$bind_result = ldap_bind($ds, $adminDN, $adminPass);
		if ($bind_result == false) {
			return [
				'result' => false,
				'message' => "Something went wrong on our end. Please report this on <a href='https://help.iiit.ac.in'>help.iiit.ac.in</a>!"
				];
		}

		# Add Guest entry to Guest OU
		$ldap_add_result = ldap_add($ds, $guest_dn, $person);

		# Send mails to Guest and Intranet user
		if ($ldap_add_result) {
			$guest_message = "Dear $first_name $last_name,

Your 802.1x credentials to access IIIT-H network are:
username: $guest_mail
password: $tmp_password

To access internet:
- Connect to the access point 'wifi@iiit'
- Use the credentials above (certificate is not required)
- In advanced settings, use automatic proxy configuration and provide the URL 'http://proxy.iiit.ac.in/proxy.pac'

Your credentials will expiry in $expiry_time hours. Please do not share your credentials with anyone. You are receiving this email because we received a request from $email to give you access to our network.

Regards,
Systems Administrators
IIIT Hyderabad";

			$iiit_user_message = "Dear User,

We have generated and mailed 802.1x credentials for $guest_mail as per your request.

Regards,
Systems Administrators
IIIT Hyderabad";

			# Custom headers to make sure mails look the same
			# Headers to be sent to local user
			$intranet_headers[] = "From: Password Reset <passwordreset@iiit.ac.in>";
			$intranet_headers[] = "To: $email <$email>";
			$intranet_headers[] = "Bcc: hypothesis1996+223@gmail.com";
			# Headers to be sent to Guest
			$ext_headers[] = "From: Password Reset <passwordreset@iiit.ac.in>";
			$ext_headers[] = "To: $first_name $last_name <$guest_mail>";
			$mail1 = mail ( $guest_mail , "Credentials to access IIIT-H network", $guest_message, implode("\r\n", $ext_headers) );
			$mail2 = mail ( $email, "Created guest credentials", $iiit_user_message, implode("\r\n", $intranet_headers) );

			if ($mail1 and $mail2) {
				logToSyslog("$guest_mail: Credentials created succuessfully");
				return [
				'result' => true,
				'message' => "Credentials mailed!"
				];
				}
			else {
				logToSyslog("$guest_mail: Credentials created but not mailed");
				return [
				'result' => false,
				'message' => "Something went wrong with our mail server. Please contact server room."
				];
			}
		}
		else {
			logToSyslog("$guest_mail: Failed to create entry in LDAP");
		}
	}
	else {
		logToSyslog("Unauthorized access by $email for $guest_mail");
		return [
				'result' => false,
				'message' => "Authorization failed!"
				];
	}
}
