#!/usr/bin/env perl
# $Id$
#
# mavis_tacplus-ng-demo-database.pl
# (C)2001-2024 Marc Huber <Marc.Huber@web.de>
# All rights reserved.
#
# Skeleton code for implementing a database backend.
# Suitable for tac_plus-ng only.
#

=pod
# Sample configurtion
# tac_plus-ng-demo-database.cfg
#
# Try this with
#      tactrace.pl --con ./tac_plus-ng-demo-database.cfg --user demo

id = spawnd {
	background = no
	listen { port = 49 }
}

id = tac_plus-ng {
	mavis module = external {
		exec = /path/to/mavis_tacplus-ng-demo-database.pl
	}
	user backend = mavis
	login backend = mavis
	pap backend = mavis
	pap password = mavis
	host world {
		address = 0.0.0.0/0
		mavis backend = yes
	}
}
=cut

use lib '/usr/local/lib/mavis/';

use strict;
use Mavis;

$| = 1;

my $in;

$/ = "\n=\n";

my @V;

while ($in = <>) {
	my ($a, $result);

	@V = ();
	$result = MAVIS_DEFERRED;

	chomp $in;

	foreach $a (split (/\n/, $in)) {
		next unless $a =~ /^(\d+) (.*)$/;
		$V[$1] = $2;
	}

	if (defined $V[AV_A_TYPE] && $V[AV_A_TYPE] ne AV_V_TYPE_TACPLUS) {
		$result = MAVIS_DOWN;
		goto bye;
	}
	if (!defined $V[AV_A_USER]){
		$V[AV_A_USER_RESPONSE] = "User not set.";
		goto fatal;
	}
	if ($V[AV_A_TACTYPE] eq AV_V_TACTYPE_HOST) {
		# return a profile based on device IP address, realm, cert data
# XXX Add your host lookup code here.
		$V[AV_A_TACPROFILE] = <<EOT
{
	key = demo
	tag = cust001,cust-ro # the "profile" rules from the user definition might use this
	welcome banner = "Hi! :-)"
}
EOT
		;
		$V[AV_A_RESULT] = AV_V_RESULT_OK;
		$result = MAVIS_FINAL;
		goto bye;
	}
	# return a profile based on user name and realm
# XXX Add your user lookup code here.
	$V[AV_A_TACPROFILE] = <<EOT
{
	# This demo uses a profile defined in user context. Other possibilities
	# include refering to an existing profile or using a rule set.
	#
	# Do NOT put comments here in real live, it's just wasting CPU.

	tag = cust001,ro # this will be evaluated in the profile, see below

	profile {
		script {
			if (device.tag != user.tag)
				deny
			if (service == shell) { 
				if (cmd == "") {
					set priv-lvl = 15
					permit
				}
				if (user.tag == ro) {
					if (cmd =~ /^show /) permit
					if (cmd =~ /^ping /) permit
					if (cmd =~ /^traceroute /) permit
					deny
				}
				if (user.tag == rw)
					permit
			}
			deny
		}
	}
}
EOT
	;
	if ($V[AV_A_TACTYPE] eq AV_V_TACTYPE_INFO) {
		$V[AV_A_RESULT] = AV_V_RESULT_OK;
		$result = MAVIS_FINAL;
		goto bye;
	}
	if ($V[AV_A_TACTYPE] eq AV_V_TACTYPE_AUTH || $V[AV_A_TACTYPE] eq AV_V_TACTYPE_CHPW) {
		if (!defined $V[AV_A_PASSWORD]){
			$V[AV_A_USER_RESPONSE] = "Password not set.";
			goto fatal;
		}
# XXX Add your password verification code here.
		if ($V[AV_A_PASSWORD] ne "demo") {
			$V[AV_A_USER_RESPONSE] = "Permission denied.";
			goto fail;
		}
		if ($V[AV_A_TACTYPE] eq AV_V_TACTYPE_AUTH) {
			$V[AV_A_RESULT] = AV_V_RESULT_OK;
			$result = MAVIS_FINAL;
			goto bye;
		}
		if ($V[AV_A_TACTYPE] eq AV_V_TACTYPE_CHPW) {
			if (!defined $V[AV_A_PASSWORD_NEW]){
				$V[AV_A_USER_RESPONSE] = "New password not set.";
				$V[AV_A_RESULT] = AV_V_RESULT_FAIL;
				$result = MAVIS_FINAL;
				goto fatal;
			}
# XXX Add your password change code here.
			$V[AV_A_RESULT] = AV_V_RESULT_OK;
			$result = MAVIS_FINAL;
			goto bye;
		}
	}

fail:
	$V[AV_A_RESULT] = AV_V_RESULT_FAIL;
	$result = MAVIS_FINAL;
	goto bye;

fatal:
	$V[AV_A_TACPROFILE] = undef;
	$result = MAVIS_FINAL;
	$V[AV_A_RESULT] = AV_V_RESULT_ERROR;

bye:
	my ($out) = "";
	for (my $i = 0; $i <= $#V; $i++) {
		if (defined $V[$i]) {
			$V[$i] =~ tr/\n/\r/;
			$V[$i] =~ s/\0//g;
			$out .= sprintf ("%d %s\n", $i, $V[$i]);
		}
	}
	$out .= sprintf ("=%d\n", $result);
	print $out;
}
