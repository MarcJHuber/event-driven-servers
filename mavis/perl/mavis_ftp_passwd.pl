#!/usr/bin/env perl
# mavis_ftp_passwd.pl
# (C)2001-2006 Marc Huber <Marc.Huber@web.de>
# All rights reserved.
#
# Sample script for testing libmavis_external.so.
#
# This script performs password authentication for FTP requests,
# based on information returned by getpwnam().
#

use strict;

use lib '/usr/local/lib/mavis';
use lib '/home/huber/DEVEL/PROJECTS/mavis/perl/'; # REMOVE #
use Mavis;

$| = 1;

my ($in);

$/ = "\n=\n";

while ($in = <>) {
	my ($a);
	my (@V);
	my (@pwent);
	my ($result);

	@V = ();
	@pwent = undef;
	$result = MAVIS_DEFERRED;

	chomp $in;

	foreach $a (split (/\n/, $in)) {
		next unless $a =~ /^(\d+) (.*)$/;
		$V[$1] = $2;
	}

	if (defined $V[AV_A_TYPE] && $V[AV_A_TYPE] ne AV_V_TYPE_FTP) {
		$result = MAVIS_DOWN;
	}
	elsif (!defined $V[AV_A_USER] || !defined $V[AV_A_PASSWORD]) {
		$V[AV_A_COMMENT] = "AV_A_USER or AV_A_PASSWORD not set";
		$V[AV_A_RESULT] = AV_V_RESULT_ERROR;
		$result = MAVIS_FINAL;
	}
	elsif (!(@pwent = getpwnam ($V[AV_A_USER]))) {
		$V[AV_A_COMMENT] = "getpwnam failed";
		$result = MAVIS_DOWN;
	} else {
		if ($pwent[1] ne crypt ($V[AV_A_PASSWORD], $pwent[1])) {
			$V[AV_A_COMMENT] = "password mismatch";
			$V[AV_A_RESULT] = AV_V_RESULT_FAIL;
			$result = MAVIS_FINAL;
		} else {
			$V[AV_A_UID] = $pwent[2];
			$V[AV_A_GID] = $pwent[3];
			$V[AV_A_HOME] = $pwent[7];
			$V[AV_A_ROOT] = "/";
			$V[AV_A_DBPASSWORD] = $V[AV_A_PASSWORD];
			$result = MAVIS_FINAL;
		}
	}

	my ($out) = "";
	for (my $i = 0; $i <= $#V; $i++) {
		$out .= sprintf ("%d %s\n", $i, $V[$i]) if defined $V[$i];
	}
	$out .= sprintf ("=%d\n", $result);
	print $out;
}
