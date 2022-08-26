#!/usr/bin/env perl
#
# mavis_tacplus_passwd.pl
# (C)2001-2015 Marc Huber <Marc.Huber@web.de>
# All rights reserved.
#
# system passwd backend for libmavis_external.so
#

=pod

Test input for authentication:
0 TACPLUS
4 $USER
8 $PASS
49 AUTH
=

printf "0 TACPLUS\n4 $USER\n8 $PASS\n49 AUTH\n=\n" | this_script.pl

Test input for authorization:
0 TACPLUS
4 $USER
49 INFO
=

printf "0 TACPLUS\n4 $USER\n49 INFO\n=\n" | this_script.pl

#######

Environment variables:

AUTHORIZE_ONLY
	Default: unset

CHPASSWD [currently experimental/untested]
	Default: unset
	If chpasswd is available on your system you may try setting this to
		"/usr/sbin/chpasswd"
	or, when running as non-root, with a suitable /etc/sudoers configuration, to
		"/usr/bin/sudo /usr/sbin/chpasswd"

=cut

use lib '/usr/local/lib/mavis/';
use lib '/Users/marc/DEVEL/PROJECTS/mavis/perl/'; # REMOVE #

use strict;
use Mavis;

my $authorize_only;
$authorize_only = $ENV{'AUTHORIZE_ONLY'} if exists $ENV{'AUTHORIZE_ONLY'};

my $SUDO;
$SUDO = $ENV{'SUDO'} if exists $ENV{'SUDO'};
my $CHPASSWD;
if (exists $ENV{'CHPASSWD'}) {
	$CHPASSWD = $ENV{'CHPASSWD'};
	$CHPASSWD = $SUDO . ' ' . $CHPASSWD if defined $SUDO;
}

my $have_getgrouplist;
if (eval "require User::getgrouplist") {
	import User::getgrouplist;
	$have_getgrouplist = 1;
}

{
	my $p = undef;
	(undef, $p) = getpwnam('root');
	if (defined($p) && $p =~ /^\**$/) {
		print STDERR
			"Warning: getpwnam() doesn't return password hashes.\n";
	}
}

$| = 1;

my ($in);

$/ = "\n=\n";

while ($in = <>) {
	my ($a, @V, $result);

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
		if (!$authorize_only && ($V[AV_A_TACTYPE] eq AV_V_TACTYPE_AUTH || $V[AV_A_TACTYPE] eq AV_V_TACTYPE_CHPW)){
			unless (crypt($V[AV_A_PASSWORD], $passwd) eq $passwd) {
				$V[AV_A_USER_RESPONSE] = "Permission denied.";
				$V[AV_A_RESULT] = AV_V_RESULT_FAIL;
				$result = MAVIS_FINAL;
				goto bye;
			}
			if ($V[AV_A_TACTYPE] eq AV_V_TACTYPE_CHPW) {
				my $CH;
				if (defined $CHPASSWD && open ($CH, "|$CHPASSWD")) {
					print $CH $V[AV_A_USER], ':', $V[AV_A_PASSWORD_NEW];
					unless (close $CH) {
						$V[AV_A_USER_RESPONSE] = $CHPASSWD . ': ' . $?;
						$V[AV_A_RESULT] = AV_V_RESULT_FAIL;
						$result = MAVIS_FINAL;
						goto bye;
					}
					$V[AV_A_DBPASSWORD] = $V[AV_A_PASSWORD_NEW];
				} else {
					$V[AV_A_USER_RESPONSE] = "Not implemented.";
					$V[AV_A_RESULT] = AV_V_RESULT_FAIL;
					$result = MAVIS_FINAL;
					goto bye;
				}
			}
		}

		$V[AV_A_GID] = $gid;
		if (my $g = getgrgid($gid)){
		    $V[AV_A_TACMEMBER] = $g;
		}

		if ($have_getgrouplist) {
		    $V[AV_A_GIDS] = join(',', getgrouplist($V[AV_A_USER]));
		} else {
			$V[AV_A_GIDS] = $gid;
			setgrent();
			while (my ($undef,undef,$g,$members) = getgrent()){
				foreach my $m (split (/\s+/, $members)){
					if ($m eq $V[AV_A_USER]) {
						$V[AV_A_GIDS] .= ',' . $g;
						last;
					}
				}
			}
			endgrent();
		}

		if (!$authorize_only && $V[AV_A_PASSWORD] && $V[AV_A_TACTYPE] eq AV_V_TACTYPE_AUTH) {
			$V[AV_A_DBPASSWORD] = $V[AV_A_PASSWORD]
		}

		if (!$authorize_only || $V[AV_A_TACTYPE] eq AV_V_TACTYPE_INFO) {
			$V[AV_A_RESULT] = AV_V_RESULT_OK;
			$result = MAVIS_FINAL;
		} else {
			$result = MAVIS_DOWN;
		}
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
