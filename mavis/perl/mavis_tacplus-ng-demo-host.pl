#!/usr/bin/env perl
# $Id$
#
# mavis_tacplus-ng-demo-host.pl
# (C)2001-2024 Marc Huber <Marc.Huber@web.de>
# All rights reserved.
#
# TACACS+ demo backend for aquiring host data
# Suitable for tac_plus-ng only.
#

=pod

Test input for authentication:
0 TACPLUS
4 $SERVER_IP
49 HOST
=

printf "0 TACPLUS\n4 127.0.0.1\n49 HOST\n=\n" | this_script.pl

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
	if ($V[AV_A_TACTYPE] ne AV_V_TACTYPE_HOST) {
		$result = MAVIS_DOWN;
		goto bye;
	}

	# demo code only!
	$V[AV_A_TACPROFILE] = "{ key = demo }";
	$V[AV_A_RESULT] = AV_V_RESULT_OK;
	$result = MAVIS_FINAL;
	goto bye;

fail:
	$V[AV_A_RESULT] = AV_V_RESULT_FAIL;
	$result = MAVIS_FINAL;
	goto bye;

down:
	$V[AV_A_RESULT] = AV_V_RESULT_NOTFOUND;
	$result = MAVIS_DOWN;
	goto bye;

fatal:
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

# vim: ts=4
