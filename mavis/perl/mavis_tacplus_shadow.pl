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

	Add new users using vipw or any other editor that performs file locking.

FLAG_PWPOLICY
    Enforce a simplicistic password policy.
    Default: unset

CI
    Absolute path to the "ci" program, used for storing revisions of the shadow file into RCS.
    Default: ci

MKPASSWD
    Absolute path to the "mkpasswd" program, most likely /usr/bin/mkpasswd
    Default: unset

MKPASSWDMETHOD
    method argument for mkpasswd, see "mkpasswd --m" for a list supported on your system.
    Use this with care.
    Default: unset

########

=cut

use lib '/usr/local/lib/mavis/';

use strict;
use POSIX qw(pipe dup2);
use Mavis;
use Fcntl ':flock';

my $hashid = ''; # DES
my $have_crypt_passwd_xs;

my $flag_pwpolicy	= undef;
my $shadow		= "/dev/null";
my $ci			= "ci";
my $mkpasswd		= undef;
my @mkpasswdmethod	= ();

$| = 1;

$shadow			= $ENV{'SHADOWFILE'} if exists $ENV{'SHADOWFILE'};
$flag_pwpolicy		= $ENV{'FLAG_PWPOLICY'} if exists $ENV{'FLAG_PWPOLICY'};
$ci			= $ENV{'CI'} if exists $ENV{'CI'};
$mkpasswd		= $ENV{'MKPASSWD'} if exists $ENV{'MKPASSWD'};
@mkpasswdmethod		= ("-m", $ENV{'MKPASSWDMETHOD'}) if exists $ENV{'MKPASSWDMETHOD'};

my $backup		= "$shadow.bak";

undef $mkpasswd unless -x $mkpasswd;

if (crypt('test', '$1$q5/vUEsR$') eq '$1$q5/vUEsR$jVwHmEw8zAmgkjMShLBg/.') {
	$hashid = '$1$'; # MD5
} elsif (eval "require Crypt::Passwd::XS") {
	import Crypt::Passwd::XS;
	$hashid = '$1$';	# MD5
	$have_crypt_passwd_xs = 1;
} elsif (undef $mkpasswd) {
	print STDERR "Your system doesn't support modern hashes. Please install the mkpasswd utility.\n";
}

sub run_mkpasswd($) {
	my ($parent0, $child1) = POSIX::pipe();
	my ($child0, $parent1) = POSIX::pipe();
	my $childpid = fork();
	if ($childpid eq 0) {
		POSIX::close $parent0;
		POSIX::close $parent1;
		POSIX::dup2($child0, 0);
		POSIX::dup2($child1, 1);
		exec $mkpasswd, "--stdin", @mkpasswdmethod;
	}
	POSIX::close $child0;
	POSIX::close $child1;
	POSIX::write($parent1, $_[0] . "\n", length($_[0]) + 1) or printf STDERR "POSIX::write: $!";
	my $cry;
	my $crylen = 1000;
	POSIX::read($parent0, $cry, $crylen) or printf STDERR "POSIX::read: $!";
	chomp $cry;
	POSIX::close $parent0;
	POSIX::close $parent1;
	waitpid($childpid, 0);
	($? == 0) ? $cry : undef;
}

sub get_password_hash ($$) {
	if ($have_crypt_passwd_xs) {
			Crypt::Passwd::XS::crypt($_[0], $_[1]);
	} else {
			crypt($_[0], $_[1]);
	}
}

sub new_password_hash ($) {
	if (defined $mkpasswd) {
		my $res = run_mkpasswd($_[0]);
		if (defined $res) {
			return $res;
		} else {
			print STDERR "mkpasswd returned an error and will now be disabled.\n";
			undef $mkpasswd;
		}
	}
	my $salt = "";
	for (my $i = 0; $i < 16; $i++) {
		$salt .= ('.', '/', 0..9, 'A'..'Z', 'a'..'z')[rand 64];
	}

	return get_password_hash($_[0], $salt);
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

	if ($V[AV_A_TACTYPE] eq AV_V_TACTYPE_AUTH) {
		unless (open ($SHADOW, "< $shadow")) {
			print STDERR "open (line " . __LINE__ . "): $!";
			$V[AV_A_USER_RESPONSE] = "Password database unavailable ($!)";
			goto fatal;
		}
	} elsif ($V[AV_A_TACTYPE] eq AV_V_TACTYPE_CHPW) {
		unless (open ($SHADOW, "+< $shadow") && flock($SHADOW, LOCK_EX)) {
			print STDERR "open (line " . __LINE__ . "): $!";
			$V[AV_A_USER_RESPONSE] = "Password database unavailable ($!)";
			goto fatal;
		}
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

	if (get_password_hash($V[AV_A_PASSWORD], $passwd) ne $passwd) {
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
	$V[AV_A_PASSWORD_EXPIRY] = 86400 * ($lastchange + $maxage);

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
			if (eval "require String::Similarity") {
				import String::Similarity;
				my $sim = similarity ($V[AV_A_PASSWORD], $V[AV_A_PASSWORD_NEW]);
				if ($sim > 0.5) {
					$V[AV_A_USER_RESPONSE] = "Old and new password are too similar (factor: $sim).";
					goto fail;
				}
			} else {
				print STDERR "Adding  String::Similarity is recommended for password similiarity checking";
			}
		}

		my @M = fgrep ($v, \@L, 1);
		goto fail if $#M + 1 != $#L;

		my $encpw = new_password_hash ($V[AV_A_PASSWORD_NEW]);

		push @M, "$user:$encpw:$today:$minage:$maxage:$warn:$remainder";

		# ci may modify the original file, messing with our lock.
		system("cp $shadow $backup && $ci -l $backup </dev/null 2>/dev/null >&2");

		truncate $SHADOW, 0;
		seek($SHADOW, 0, 0);
		print $SHADOW join('', @M);
		close $SHADOW;
		
		$V[AV_A_USER_RESPONSE] = "Password change was successful.";
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
