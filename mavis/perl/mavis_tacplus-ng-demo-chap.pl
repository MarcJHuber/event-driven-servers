#!/usr/bin/env perl
# $Id$
#
# mavis_tacplus-demo-chap.pl
# (C)2026 Marc Huber <Marc.Huber@web.de>
# All rights reserved.
#
# Sample CHAP backend. Hard-coded password is "demo".
#

=pod

Test input for authentication:
0 TACPLUS
4 $USER
51 $PPPID $CHALLENGE $RESPONSE
49 CHAP
=


Test (with pppid: 0x58, challenge: 0x585858, password: demo):
 printf "0 TACPLUS\n4 demo\n51 58 585858 e900519a3962395837a6275ed7a53bc5\n49 CHAP\n=\n" | ./mavis_tacplus-ng-demo-chap.pl

########

=cut

use lib '/usr/local/lib/mavis/';

use strict;
use Digest::MD5 qw(md5);
use Mavis;

$| = 1;

my ($in);

$/ = "\n=\n";

while ($in = <>) {
	my @V = ();
	my $result = MAVIS_DEFERRED;

	chomp $in;

	foreach my $a (split (/\n/, $in)) {
		next unless $a =~ /^(\d+) (.*)$/;
		$V[$1] = $2;
	}

	if (!defined $V[AV_A_USER]){
		$V[AV_A_USER_RESPONSE] = "User not set.";
		goto fatal;
	}
	if (!defined $V[AV_A_TYPE] || ($V[AV_A_TYPE] ne AV_V_TYPE_TACPLUS) || !defined $V[AV_A_TACTYPE] || ($V[AV_A_TACTYPE] ne AV_V_TACTYPE_CHAP)) {
		$result = MAVIS_DOWN;
		goto bye;
	}
	if (!defined $V[AV_A_CHALLENGE]){
		$V[AV_A_USER_RESPONSE] = "Challenge/Response not set.";
		goto fatal;
	}
	if (uc $V[AV_A_CHALLENGE] !~ /^([0-9a-fA-F]{2}) ([0-9a-fA-F]+) ([0-9a-fA-F]+)$/) {
		$V[AV_A_USER_RESPONSE] = "Challenge/Response invalid.";
		goto fatal;
	}
	my $password = "demo"; # FIXME

	my ($pppid, $challenge, $response) = (pack("H*", $1), pack("H*", $2), pack("H*", $3));
	if ($response eq md5($pppid, $password, $challenge)) {
		$V[AV_A_RESULT] = AV_V_RESULT_OK;
	} else {
		$V[AV_A_RESULT] = AV_V_RESULT_FAIL;
	}

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
		$out .= sprintf ("%d %s\n", $i, $V[$i]) if defined $V[$i];
	}
	$out .= sprintf ("=%d\n", $result);
	print $out;

	$/ = "\n=\n";
}

# vim: ts=4
