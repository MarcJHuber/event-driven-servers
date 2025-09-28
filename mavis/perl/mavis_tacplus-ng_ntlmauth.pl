#!/usr/bin/env perl
# $Id$
#
# mavis_tacplus_ntlmauth.pl
# (C)2025 Marc Huber <Marc.Huber@web.de>
# All rights reserved.
#
# Shadow password backend for libmavis_external.so
# MSCHAP authentication using SAMBA's ntlm_auth tool. Requires winbindd et al. to
# be running on your system.
#

=pod

Test input for authentication:
0 TACPLUS
4 $USER
51 $CHALLENGE $RESPONSE
49 MSCH
=

#######

Environment variables:

NTLM_AUTH
    Path to your ntlm_auth binary
    Default: /usr/bin/ntlm_auth

NT_DOMAIN
    Your NT domain.
    Default: EXAMPLE

########

=cut

use lib '/usr/local/lib/mavis/';

use strict;
use IPC::Open3;
use Mavis;

$| = 1;

my $NTLM_AUTH = "/usr/bin/ntlm_auth";
my $NT_DOMAIN = "EXAMPLE";

$NTLM_AUTH		= $ENV{'NTLM_AUTH'} if exists $ENV{'NTLM_AUTH'};
$NT_DOMAIN		= $ENV{'NT_DOMAIN'} if exists $ENV{'NT_DOMAIN'};

sub run_ntlmauth($$) {
	my $pid = open3(my $chld_in, my $chld_out, undef,
		$NTLM_AUTH, '--helper-protocol=ntlm-server-1', '--allow-mschapv2');

	print $chld_in $_[0];
	close $chld_in;

	my $res = 1;
	local $/ = "\n";
	while (<$chld_out>) {
		if (/^Authentication-Error:\s(.*)$/) {
			print STDERR $_;
			$_[1] = $_;
		} else {
			$res = 0 if /^Authenticated: Yes\n$/;
		}
	}
	close $chld_out;
	waitpid($pid, 0);
	$res;
}

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
	if (!defined $V[AV_A_TYPE] || ($V[AV_A_TYPE] ne AV_V_TYPE_TACPLUS) || !defined $V[AV_A_TACTYPE] || ($V[AV_A_TACTYPE] ne AV_V_TACTYPE_MSCHAP)) {
		$result = MAVIS_DOWN;
		goto bye;
	}
	if (!defined $V[AV_A_CHALLENGE]){
		$V[AV_A_USER_RESPONSE] = "Challenge/Response not set.";
		goto fatal;
	}
	if (uc $V[AV_A_CHALLENGE] !~ /^([0-9a-fA-F]{16}) ([0-9a-fA-F]{48})$/) {
		$V[AV_A_USER_RESPONSE] = "Challenge/Response invalid.";
		goto fatal;
	}
	my $err = undef;
	if (run_ntlmauth(
		"Username: " . $V[AV_A_USER] . "\n" .
		"NT-Domain: " . $NT_DOMAIN . "\n" .
		"LANMAN-Challenge: " . $1 . "\n" .
		"NT-Response: " . $2 . "\n" .
		".\n", $err
	   )) {
		$V[AV_A_RESULT] = AV_V_RESULT_FAIL;
		$V[AV_A_USER_RESPONSE] = $err if $err;
	} else {
		$V[AV_A_RESULT] = AV_V_RESULT_OK;
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
