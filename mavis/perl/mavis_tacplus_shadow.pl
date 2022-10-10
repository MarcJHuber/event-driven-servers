#!/usr/bin/env perl
# $Id$
#
# mavis_tacplus_shadow.pl
# (C)2011 Marc Huber <Marc.Huber@web.de>
# All rights reserved.
#
# Shadow password backend for libmavis_external.so
# Authenticates against local shadow password file, supports password changes.
#

=pod

Test input for authentication:
0 TACPLUS
4 $USER
8 $PASS
49 AUTH
=

printf "0 TACPLUS\n4 $USER\n8 $PASS\n49 AUTH\n=\n" | this_script.pl

Test input for password change:
0 TACPLUS
4 $USER
8 $PASS
49 CHPW
50 $NEWPASS
=

printf "0 TACPLUS\n4 $USER\n8 $PASS\n49 CHPW\n50 $NEWPASS\n=\n" | this_script.pl

#######

Environment variables:

SHADOWFILE
    Absolute path to your shadow file.
    Default: /dev/null

	Shadow file syntax:
	username:encpass:lastchange:minage:maxage:warn:...

	Setting lastchange to 0 enforces password change at initial log-in.

	Example:
	marc:$1$oAY9rv/9$NuyhEqJNSROHmLlwCXv0T.:15218:0:99999:7:::
	test:$1$oAY9rv/9$NuyhEqJNSROHmLlwCXv0T.:15213:0:99999:7:::
	test2:$1$oAY9rv/9$NuyhEqJNSROHmLlwCXv0T.:0:0:99999:7:::

	to use SHA512 hashes you should install:
	cpan install Crypt::Passwd::XS

	Add new users using vipw or any other editor that performs file locking.

FLAG_PWPOLICY
    Enforce a simplicistic password policy.
    Default: unset

CI
	Absolute path to the "ci" program, used for storing revisions of the
	shadow file into RCS.
	Default: ci

########

=cut

use lib '/usr/local/lib/mavis/';
use lib '/Users/marc/DEVEL/PROJECTS/mavis/perl/'; # REMOVE #

use strict;
use Mavis;
use Fcntl ':flock';

my $hashid = ''; # DES
my $have_crypt_passwd_xs;

if (eval "require Crypt::Passwd::XS") {
	import Crypt::Passwd::XS;
	$hashid = '$6$'; # SHA512
	$have_crypt_passwd_xs = 1;
} elsif (crypt('test', '$1$q5/vUEsR$') eq '$1$q5/vUEsR$jVwHmEw8zAmgkjMShLBg/.') {
	$hashid = '$1$'; # MD5
} else {
	print STDERR "Your system doesn't support MD5 hashes. Please consider running 'cpan install Crypt::Passwd::XS'\n";
}

sub mycrypt ($$) {
	if ($have_crypt_passwd_xs) {
			Crypt::Passwd::XS::crypt($_[0], $_[1]);
	} else {
			crypt($_[0], $_[1]);
	}
}

sub fgrep ($$$) {
	my ($v, $L, $negate) = @_;
	my @Q = ();
	foreach my $line(@{$L}) {
		my ($u, $r);
		($u, $r) = split(/:/, $line, 2);
		if (($negate && ($u ne $v)) || (!$negate && ($u eq $v))) {
			push(@Q, $line);
		}
	}
	return @Q;
}

umask 0177;

my $flag_pwpolicy	= undef;
my $shadow			= "/dev/null";
my $ci				= "ci";

$shadow				= "/Users/marc/tmp/shadow"; # REMOVE #
$shadow				= $ENV{'SHADOWFILE'} if exists $ENV{'SHADOWFILE'};
$flag_pwpolicy		= $ENV{'FLAG_PWPOLICY'} if exists $ENV{'FLAG_PWPOLICY'};
$ci					= $ENV{'CI'} if exists $ENV{'CI'};

my $backup			= "$shadow.bak";

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
	if (!defined $V[AV_A_TYPE] || ($V[AV_A_TYPE] ne AV_V_TYPE_TACPLUS) ||
		!defined $V[AV_A_TACTYPE] || (($V[AV_A_TACTYPE] ne AV_V_TACTYPE_AUTH) &&
									  ($V[AV_A_TACTYPE] ne AV_V_TACTYPE_CHPW))) {
		$result = MAVIS_DOWN;
		goto bye;
	}
	if (!defined $V[AV_A_PASSWORD]){
		$V[AV_A_USER_RESPONSE] = "Password not set.";
		goto fatal;
	}
	if ($V[AV_A_TACTYPE] eq AV_V_TACTYPE_CHPW && !defined $V[AV_A_PASSWORD_NEW]){
		$V[AV_A_USER_RESPONSE] = "New password not set";
		goto fatal;
	}

	my $SHADOW = undef;

	unless (open ($SHADOW, "+< $shadow") && flock($SHADOW, LOCK_EX)) {
		$V[AV_A_USER_RESPONSE] = "Password database unavailable";
		goto fatal;	
	}

	$/ = "\n";

	my @L = <$SHADOW>;

	close $SHADOW if $V[AV_A_TACTYPE] eq AV_V_TACTYPE_AUTH;

	my $v = $V[AV_A_USER];
	my @Q = fgrep ($v, \@L, 0);
	goto down if $#Q == -1;
	goto fail unless $#Q == 0;
	my $line = $Q[0];

	my ($user, $passwd, $lastchange, $minage, $maxage, $warn, $remainder);
	$warn = 0;
	($user, $passwd, $lastchange, $minage, $maxage, $warn, $remainder) = split(/:/, $line, 7) or
	($user, $passwd, $lastchange, $minage, $maxage, $remainder) = split(/:/, $line, 6) or
	goto down;

	$warn = 0 if $warn !~ /^\d+$/;

	if (mycrypt($V[AV_A_PASSWORD], $passwd) ne $passwd) {
		$V[AV_A_USER_RESPONSE] = "Permission denied.";
		goto fail;
	}

	my $today = int scalar(time)/86400;

	if ($lastchange == 0 || $lastchange + $maxage < $today) {
		$V[AV_A_PASSWORD_MUSTCHANGE] = "y";
		$V[AV_A_USER_RESPONSE] = "Please change your password.";
	} elsif ($lastchange + $maxage - $warn < $today) {
		my $d = $lastchange + $maxage - $today;
		my $ds = ($d == 1) ? "" : "s";
		$V[AV_A_USER_RESPONSE] = "Please change your password. "
			. "It will expire in $d day$ds.";
	}

	if ($V[AV_A_TACTYPE] eq AV_V_TACTYPE_CHPW) {
		if ($minage > 0 && $today < $lastchange + $minage) {
				my $d = $lastchange + $minage - $today;
				my $ds = ($d == 1) ? "" : "s";
				$V[AV_A_USER_RESPONSE] = "Need to wait $d day$ds until next password change.";
				goto fail;
		}

	    if (defined($flag_pwpolicy)) {
			# Reject passwords that are obviously too weak:
			if ($V[AV_A_PASSWORD_NEW] =~ /^.?.?.?.?.?.?.?$/ || $V[AV_A_PASSWORD_NEW] !~ /\d/
			 || $V[AV_A_PASSWORD_NEW] !~ /[a-z]+/ || $V[AV_A_PASSWORD_NEW] !~ /[A-Z]+/){
				$V[AV_A_USER_RESPONSE] =
				"Password must consist of at least 8 characters, ".
				"include an uppercase letter, a lowercase letter ".
				"and a digit.";
				goto fail;
			}
		}

		my @M = fgrep ($v, \@L, 1);
	    goto fail if $#M + 1 != $#L;

		my $salt = "";
		for (my $i = 0; $i < 16; $i++) {
			$salt .= ('.', '/', 0..9, 'A'..'Z', 'a'..'z')[rand 64];
		}

		my $encpw = mycrypt ($V[AV_A_PASSWORD_NEW], $hashid . $salt);

		push @M, "$user:$encpw:$today:$minage:$maxage:$warn:$remainder";

		# ci may modify the original file, messing with our lock.
		system("cp $shadow $backup && $ci -l $backup </dev/null 2>/dev/null >&2");

		truncate $SHADOW, 0;
		seek($SHADOW, 0, 0);
		print $SHADOW join('', @M);
		close $SHADOW;
		
		$V[AV_A_DBPASSWORD] = $V[AV_A_PASSWORD_NEW];
		$V[AV_A_USER_RESPONSE] = "Password change was successful.";
	} else {
		$V[AV_A_DBPASSWORD] = $V[AV_A_PASSWORD];
	}

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

	close $SHADOW if defined $SHADOW && fileno $SHADOW;

	my ($out) = "";
	for (my $i = 0; $i <= $#V; $i++) {
		$out .= sprintf ("%d %s\n", $i, $V[$i]) if defined $V[$i];
	}
	$out .= sprintf ("=%d\n", $result);
	print $out;

	$/ = "\n=\n";
}

# vim: ts=4
