<?php
/*
 *
 * @author: Jyotish P <srisai.poonganam@research.iiit.ac.in>
 *
 *
*/

$allowed_ips=array('127.0.0.1');

if (!in_array($_SERVER['REMOTE_ADDR'], $allowed_ips)) {
	echo "Sorry, access denied!";
	exit(0);
}

require_once '../config.php';
require_once 'utils.php';

$posted_data = false;
$email = $_POST['iiit_mail'];
$password = $_POST['password'];
$first_name = htmlspecialchars($_POST['first_name']);
$last_name = htmlspecialchars($_POST['last_name']);
$guest_mail = $_POST['mail'];
$phone = htmlspecialchars($_POST['phone']);
$expiry_time = htmlspecialchars($_POST['expiry_time']);

if (
	$email !== '' and
	$password !== '' and
	$first_name !== '' and
	$last_name !== '' and
	$guest_mail !== '' and
	$phone !== ''
) {
	$result = add_ldap_entry( $email,
		              $password,
		              $first_name,
		              $last_name,
		              $guest_mail,
		              $phone,
								  $expiry_time);
	$posted_data = true;
}

?>

<!doctype html>
<html lang="en">
<head>
	<meta charset="utf-8" />
	<meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1" />
	<link rel="apple-touch-icon" sizes="76x76" href="assets/img/favicon.ico">

	<title>Guest Credentials Portal | IIIT Hyderabad</title>

	<meta content='width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=0' name='viewport' />
	<meta name="viewport" content="width=device-width" />

	<link rel="apple-touch-icon" sizes="76x76" href="assets/img/apple-icon.png" />
	<link rel="icon" type="image/png" href="assets/img/favicon.png" />

	<!--     Fonts and icons     -->
	<link rel="stylesheet" type="text/css" href="https://fonts.googleapis.com/css?family=Roboto:300,400,500,700|Roboto+Slab:400,700|Material+Icons" />
	<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/font-awesome/latest/css/font-awesome.min.css" />

	<!-- CSS Files -->
	<link href="/guest/static/css/bootstrap.min.css" rel="stylesheet" />
	<link href="/guest/static/css/material-bootstrap-wizard.css" rel="stylesheet" />

	<!-- CSS Just for demo purpose, don't include it in your project -->
	<link href="/guest/static/css/guest.css" rel="stylesheet" />
</head>

<body>
	<div class="image-container set-full-height">
		<!--   Creative Tim Branding   -->
		<a href="https://iiit.ac.in">
			 <div class="logo-container">
				<div class="logo">
					<img src="/guest/static/img/new_logo.png">
				</div><!--
				<div class="brand">
					IIIT Hyderabad
				</div> -->
			</div>
		</a>

		<!--  Made With Material Kit  -->
		<!-- a href="https://help.iiit.ac.in" class="made-with-mk">
			<div class="brand"><i class="material-icons">help</i></div>
			<div class="made-with">Raise a ticket at help</div>
		</a> -->

		<!--   Big container   -->
		<div class="container">
			<div class="row">
				<div class="col-sm-8 col-sm-offset-2">
					<!--      Wizard container        -->
					<div class="wizard-container">
						<div class="card wizard-card" data-color="green" id="wizardProfile">
							<form action="/guest" method="POST">
						<!--        You can switch " data-color="purple" "  with one of the next bright colors: "green", "orange", "red", "blue"       -->

								<div class="wizard-header">
									<h3 class="wizard-title">Guest Credentials Generator</h3>
									<h5>The credentials can only be used to access IIIT-H network</h5>
									<?php if ($posted_data) { ?>
									<h5 style="color: <?= ($result)? 'green">Credentials mailed!' : 'red">Something went wrong :(' ?></h5>
									<?php } ?>
								</div>
								<div class="wizard-navigation">
									<ul id="wizard-tabs">
										<li><a href="#auth" data-toggle="tab">Authorization</a></li>
										<li><a href="#account" data-toggle="tab">Account Details</a></li>
										<!-- <li><a href="#address" data-toggle="tab">Address</a></li> -->
									</ul>
								</div>

								<div class="tab-content">
									<div class="tab-pane" id="auth">
										<div class="row">
											<h4 class="info-text"> Please provide your IIIT-H credentials to proceed</h4>
											<div class="col-sm-6 col-sm-push-3">
												<div class="col-sm-12">
													<div class="input-group">
														<span class="input-group-addon">
															<i class="material-icons">account_circle</i>
														</span>
														<div class="form-group label-floating">
														  <label class="control-label">E-Mail <small>(required)</small></label>
														  <input id="iiit_mail" name="iiit_mail" type="email" class="form-control">
														</div>
													</div>
												</div>
												<div class="col-sm-12">
													<div class="input-group">
														<span class="input-group-addon">
															<i class="material-icons">security</i>
														</span>
														<div class="form-group label-floating">
														  <label class="control-label">Password <small>(required)</small></label>
														  <input id="password" name="password" type="password" class="form-control">
														</div>
													</div>
												</div>
											</div>
										</div>
									</div>

									<div class="tab-pane" id="account">
									  <div class="row">
											<h4 class="info-text"> Let's start with the basic information (with validation)</h4>
											<div class="col-sm-6">
												<div class="input-group">
													<span class="input-group-addon">
														<i class="material-icons">face</i>
													</span>
													<div class="form-group label-floating">
													  <label class="control-label">First Name <small>(required)</small></label>
													  <input name="first_name" type="text" class="form-control">
													</div>
												</div>
											</div>
											<div class="col-sm-6">
												<div class="input-group">
													<span class="input-group-addon">
														<i class="material-icons">record_voice_over</i>
													</span>
													<div class="form-group label-floating">
													  <label class="control-label">Last Name <small>(required)</small></label>
													  <input name="last_name" type="text" class="form-control">
													</div>
												</div>
											</div>
											<div class="col-sm-5">
												<div class="input-group">
													<span class="input-group-addon">
														<i class="material-icons">alarm_off</i>
													</span>
													<div class="form-group label-floating">
														<label class="control-label">Expiry (in Hours) #</label>
														<input id="slider" type="range" min="1" max="48" step="1" value="24" class="slider-success">
													</div>
												</div>
											</div>
											<div class="col-sm-1">
												<div class="input-group">
													<div class="form-group label-floating">
														<label class="control-label"><small>(required)</small></label>
														<input id="expiry_time" name="expiry_time" type="tel" value="24" class="form-control">
													</div>
												</div>
											</div>
											<div class="col-sm-6">
												<div class="input-group">
													<span class="input-group-addon">
														<i class="material-icons">phone</i>
													</span>
													<div class="form-group label-floating">
														<label class="control-label">Mobile # <small>(required)</small></label>
														<input name="phone" type="tel" class="form-control">
													</div>
												</div>
											</div>
											<div class="col-sm-12">
												<div class="input-group">
													<span class="input-group-addon">
														<i class="material-icons">email</i>
													</span>
													<div class="form-group label-floating">
														<label class="control-label">Email <small>(required)</small></label>
														<input id="mail" name="mail" type="email" class="form-control">
														<small>Password will be mailed to this address</small>
													</div>
												</div>
											</div>
										</div>
									</div>
								</div>
								<div class="wizard-footer">
									<div class="pull-right">
										<input type='button' class='btn btn-next btn-fill btn-success btn-wd' name='next' value='Next' />
										<input type='submit' class='btn btn-finish btn-fill btn-success btn-wd' name='finish' value='Finish' />
									</div>

									<div class="pull-left">
										<input type='button' class='btn btn-previous btn-fill btn-default btn-wd' name='previous' value='Previous' />
									</div>
									<div class="clearfix"></div>
								</div>
							</form>
						</div>
					</div> <!-- wizard container -->
				</div>
			</div><!-- end row -->
		</div> <!--  big container -->

		<div class="footer">
			<div class="container text-center">
				<a href="https://help.iiit.ac.in">Report any issues at help.iiit.ac.in</a>
			</div>
		</div>
	</div>

</body>
	<!--   Core JS Files   -->
	<script src="/guest/static/js/jquery-2.2.4.min.js" type="text/javascript"></script>
	<script src="/guest/static/js/bootstrap.min.js" type="text/javascript"></script>
	<script src="/guest/static/js/jquery.bootstrap.js" type="text/javascript"></script>

	<!--  Plugin for the Wizard -->
	<script src="/guest/static/js/guest.js"></script>

	<!--  More information about jquery.validate here: http://jqueryvalidation.org/	 -->
	<script src="/guest/static/js/jquery.validate.min.js"></script>

</html>
