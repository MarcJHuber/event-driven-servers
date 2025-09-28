#!/usr/bin/env perl
# $Id$
#
# mavis_tacplus_ntmlauth.pl
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
use POSIX qw(pipe dup2);
use Mavis;

$| = 1;

my $NTLM_AUTH = "/usr/bin/ntml_auth";
my $NT_DOMAIN = "EXAMPLE";

$NTLM_AUTH		= $ENV{'NTLM_AUTH'} if exists $ENV{'NTLM_AUTH'};
$NT_DOMAIN		= $ENV{'NT_DOMAIN'} if exists $ENV{'NT_DOMAIN'};

sub run_ntlmauth($) {
	my ($parent0, $child1) = POSIX::pipe();
	my ($child0, $parent1) = POSIX::pipe();
	my $childpid = fork();
	if ($childpid eq 0) {
		POSIX::close $parent0;
		POSIX::close $parent1;
		POSIX::dup2($child0, 0);
		POSIX::dup2($child1, 1);
		exec $NTLM_AUTH, "--helper-protocol=ntlm-server-1", "--allow-mschapv2";
	}
	POSIX::close $child0;
	POSIX::close $child1;
	POSIX::write($parent1, $_[0], length($_[0])) or printf STDERR "POSIX::write: $!";
	POSIX::close $parent0;
	POSIX::close $parent1;
	waitpid($childpid, 0);
	$?;
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
	if (run_ntlmauth(
		"Username: " . $V[AV_A_USER] . "\n" .
		"NT-Domain: " . $NT_DOMAIN . "\n" .
		"LANMAN-Challenge: " . $1 . "\n" .
		"NT-Response: " . $2 . "\n" .
		".\n"
	   )) {
		$V[AV_A_RESULT] = AV_V_RESULT_FAIL;
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
