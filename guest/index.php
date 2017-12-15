<?php
/* 
 *
 * @author: Parth Laxmikant Kolekar <parth.kolekar@students.iiit.ac.in>
 * @version: 1.0.0dev1
 *
*/

$allowed_ips=array('127.0.0.1');
if (!in_array($_SERVER['REMOTE_ADDR'], $allowed_ips)) {
	echo "Sorry, access denied!";
	exit(0);
}

require_once '../config.php';

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
	<link href="static/css/bootstrap.min.css" rel="stylesheet" />
	<link href="static/css/material-bootstrap-wizard.css" rel="stylesheet" />

	<!-- CSS Just for demo purpose, don't include it in your project -->
	<link href="static/css/guest.css" rel="stylesheet" />
</head>

<body>
	<div class="image-container set-full-height">
		<!--   Creative Tim Branding   -->
		<a href="https://iiit.ac.in">
			 <div class="logo-container">
				<div class="logo">
					<img src="static/img/new_logo.png">
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
							<form action="" method="">
						<!--        You can switch " data-color="purple" "  with one of the next bright colors: "green", "orange", "red", "blue"       -->

								<div class="wizard-header">
									<h3 class="wizard-title">Guest Credentials Generator</h3>
									<h5>The credentials can only be used to access IIIT-H network</h5>
								</div>
								<div class="wizard-navigation">
									<ul>
										<li><a href="#about" data-toggle="tab">Account Details</a></li>
										<!-- <li><a href="#result" data-toggle="tab">Result</a></li> -->
										<!-- <li><a href="#address" data-toggle="tab">Address</a></li> -->
									</ul>
								</div>

								<div class="tab-content">
									<div class="tab-pane" id="about">
									  <div class="row">
											<h4 class="info-text"> Let's start with the basic information (with validation)</h4>
											<div class="col-sm-6">
												<div class="input-group">
													<span class="input-group-addon">
														<i class="material-icons">face</i>
													</span>
													<div class="form-group label-floating">
													  <label class="control-label">First Name <small>(required)</small></label>
													  <input name="givenName" type="text" class="form-control">
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
													  <input name="sn" type="text" class="form-control">
													</div>
												</div>
											</div>
											<div class="col-sm-6">
												<div class="input-group">
													<span class="input-group-addon">
														<i class="material-icons">email</i>
													</span>
													<div class="form-group label-floating">
														<label class="control-label">Email <small>(required)</small></label>
														<input name="mail" type="email" class="form-control">
														<small>Password will be mailed to this address</small>
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
														<input name="telephoneNumber" type="tel" class="form-control">
													</div>
												</div>
											</div>
										</div>
									</div>
<!-- 									<div class="tab-pane" id="result">
									</div> -->
								</div>
								<div class="wizard-footer">
									<div class="pull-right">
										<input type='button' class='btn btn-next btn-fill btn-success btn-wd' name='next' value='Next' />
										<input type='button' class='btn btn-finish btn-fill btn-success btn-wd' name='finish' value='Finish' />
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
	<script src="static/js/jquery-2.2.4.min.js" type="text/javascript"></script>
	<script src="static/js/bootstrap.min.js" type="text/javascript"></script>
	<script src="static/js/jquery.bootstrap.js" type="text/javascript"></script>

	<!--  Plugin for the Wizard -->
	<script src="static/js/guest.js"></script>

	<!--  More information about jquery.validate here: http://jqueryvalidation.org/	 -->
	<script src="static/js/jquery.validate.min.js"></script>

</html>