#!/usr/bin/env perl
#
# mavis_tacplus_opie.pl
# (C)2001-2013 Marc Huber <Marc.Huber@web.de>
# All rights reserved.
#
# OPIE passwd backend for libmavis_external.so
#

# Test input: Phase 1: Retrieve challenge
# 0 TACPLUS
# 4 $USER
# 49 CHAL
# =
#
# Test input: Phase 2: Authenticate
# 0 TACPLUS
# 4 $USER
# 8 $PASS
# 49 AUTH
# =

use lib '/usr/local/lib/mavis/';
use lib '/home/huber/DEVEL/PROJECTS/mavis/perl/'; # REMOVE #

use strict;
use Authen::OPIE qw(opie_challenge opie_verify);
use Mavis;

print STDERR "Warning: You're not running as root, so OPIE password verification won't work.\n"
	unless $> == 0;

$| = 1;

my ($in);

$/ = "\n=\n";

while ($in = <>) {
	my ($a, @V, $result, $opie);

	@V = ();
	$result = MAVIS_DEFERRED;

	chomp $in;

	foreach $a (split (/\n/, $in)) {
		next unless $a =~ /^(\d+) (.*)$/;
		$V[$1] = $2;
	}
	if (defined $V[AV_A_TYPE] && $V[AV_A_TYPE] ne AV_V_TYPE_TACPLUS) {
		$result = MAVIS_DOWN;
	}
	elsif (!defined $V[AV_A_USER]){
		$V[AV_A_USER_RESPONSE] = "User not set.";
		$V[AV_A_RESULT] = AV_V_RESULT_ERROR;
		$result = MAVIS_FINAL;
	}
	elsif ($V[AV_A_USER] !~ /[-0-9a-z_]+/i){
		$V[AV_A_USER_RESPONSE] = "User name not valid.";
		$V[AV_A_RESULT] = AV_V_RESULT_ERROR;
		$result = MAVIS_FINAL;
	}
	elsif ($V[AV_A_TACTYPE] eq AV_V_TACTYPE_AUTH &&
		!defined $V[AV_A_PASSWORD]){
		$V[AV_A_USER_RESPONSE] = "Password not set.";
		$V[AV_A_RESULT] = AV_V_RESULT_ERROR;
		$result = MAVIS_FINAL;
	}
	elsif ($V[AV_A_TACTYPE] eq AV_V_TACTYPE_CHPW &&
		(!defined $V[AV_A_PASSWORD]||!defined $V[AV_A_PASSWORD_NEW])){
		$V[AV_A_USER_RESPONSE] = "Old or new password not set";
		$V[AV_A_RESULT] = AV_V_RESULT_ERROR;
		$result = MAVIS_FINAL;
	}
	else {
		my ($name, $passwd, $gid);
		unless (($name, $passwd, undef, $gid) = getpwnam($V[AV_A_USER])) {
			$V[AV_A_RESULT] = AV_V_RESULT_NOTFOUND;
			$result = MAVIS_DOWN;
			goto bye;
		}
		if ($V[AV_A_TACTYPE] eq AV_V_TACTYPE_AUTH
			||  $V[AV_A_TACTYPE] eq AV_V_TACTYPE_CHPW){
				$opie = 2;
				if ((crypt($V[AV_A_PASSWORD], $passwd) ne $passwd) &&
				    ($opie = opie_verify($name, $V[AV_A_PASSWORD]))) {
					$V[AV_A_USER_RESPONSE] = "Permission denied.";
					$V[AV_A_RESULT] = AV_V_RESULT_FAIL;
					$result = MAVIS_FINAL;
					goto bye;
				}
				if ($V[AV_A_TACTYPE] eq AV_V_TACTYPE_CHPW){
					$V[AV_A_USER_RESPONSE] = "Not implemented.";
					$V[AV_A_RESULT] = AV_V_RESULT_FAIL;
					$result = MAVIS_FINAL;
					goto bye;
				}
			}

			if ($V[AV_A_TACTYPE] eq AV_V_TACTYPE_CHAL){
				$V[AV_A_CHALLENGE] = opie_challenge($name);
			}

			if (my $g = getgrgid($gid)){
				$V[AV_A_TACMEMBER] = $g;
			}

			setgrent();
			while (my ($g,undef,undef,$members) = getgrent()){
				foreach my $m (split (/\s+/, $members)){
					if ($m eq $V[AV_A_USER]) {
						$V[AV_A_TACMEMBER] .= ',' . $g;
						last;
					}
				}
			}
			endgrent();

			$V[AV_A_DBPASSWORD] = $V[AV_A_PASSWORD]
				if defined $V[AV_A_PASSWORD] &&
					$V[AV_A_TACTYPE] eq AV_V_TACTYPE_AUTH &&
					$opie == 2;

			$V[AV_A_RESULT] = AV_V_RESULT_OK;
			$result = MAVIS_DOWN;
	}

bye:
	my ($out) = "";
	for (my $i = 0; $i <= $#V; $i++) {
		$out .= sprintf ("%d %s\n", $i, $V[$i]) if defined $V[$i];
	}
	$out .= sprintf ("=%d\n", $result);
	print $out;
}

# vim: ts=4
