#!/usr/bin/env perl
# $Id$
#
# mavis_tacplus-ng-demo-mfa.pl
# (C)2001-2026 Marc Huber <Marc.Huber@web.de>
# All rights reserved.
#
# Sample MFA-only backend
# Suitable for tac_plus-ng only.
#
# Sample configuration (tac_plus-ng/sample/tac_plus-ng-demo-database.cfg):
#

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

	if (defined $V[AV_A_TYPE] && $V[AV_A_TYPE] ne AV_V_TYPE_TACPLUS || $V[AV_A_TACTYPE] ne AV_V_TACTYPE_MFA) {
		$result = MAVIS_DOWN;
		goto bye;
	}
	if (!defined $V[AV_A_USER]){
		$V[AV_A_USER_RESPONSE] = "User not set.";
		goto fatal;
	}

	if (-f "/tmp/mfa-succeeded") {
		$V[AV_A_RESULT] = AV_V_RESULT_OK
	} else {
		$V[AV_A_RESULT] = AV_V_RESULT_FAIL;
		$V[AV_A_USER_RESPONSE] = "MFA failed";
	}

	$result = MAVIS_FINAL;
	goto bye;

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
