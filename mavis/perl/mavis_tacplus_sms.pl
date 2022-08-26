#!/usr/bin/env perl
#
# mavis_tacplus_sms.pl
# (C)2001-2009 Marc Huber <Marc.Huber@web.de>
# All rights reserved.
#
# Sample SMS OTP backend for libmavis_external.so. Implements
# two-factor authentication with OTP notification via SMS.

# Test input: Phase 1: Retrieve challenge
# 0 TACPLUS
# 4 $USER
# 14 1.2.3.4
# 49 CHAL
# =
#
# Test input: Phase 2: Authenticate
# 0 TACPLUS
# 4 $USER
# 8 $PASS
# 14 1.2.3.4
# 49 AUTH
# =


use lib '/usr/local/lib/mavis/';
use lib '/home/huber/DEVEL/PROJECTS/mavis/perl/'; # REMOVE #

use strict;
use Mavis;
use Digest::MD5 qw(md5_hex);
use POSIX qw(strftime);
use Fcntl ':mode';

# This is where OTP data is stored. Please use a safer location:
my $base = "/tmp/sms-otp/"; # FIXME

# The OT password will be valid for $otp_window seconds only:
my $otp_window = 120;

# The password is expected to be >= $otp_len characters, where the first
# $otp_len chars represent the OTP, and the remainder is the password (PIN)
# for a downstream module (PAM, for example).
#
# The downstream module may choose to omit the passwort check, if
# supported and configured accordingly.
my $otp_len = 6;

my $sendmail = "/usr/sbin/sendmail";

sub sms_send($$$) {
	my ($user, $serial, $secret) = @_;
# FIXME: Send a SMS with serial and secret to the user's mobile number.
# FIXME: It's up to you and your SMS provider on how exactly this works.

# FIXME: return undef if mobile number not known

# FIXME: For testing, but possibly reusable:

	my $SM;
	open ($SM, "|$sendmail -t") or return undef;
	print $SM <<EOT;
From: root\@localhost
To: root\@localhost
Subject: OTP for user $user

Serial: $serial
OTP: $secret
EOT
	close ($SM);

	1;	# undef: failure, defined: success
}

my $cleanup_count = 0;

sub cleanup () {
	my $DIR;
	opendir($DIR, $base) || die;
	my @entries = grep { /^[0-9a-zA-z]{64}$/ } readdir($DIR);
	closedir($DIR);

	my $now = time;
	for my $entry (@entries) {
		my $mode;
		my $mtime;
		(undef,undef,$mode,undef,undef,undef,undef,
			undef, undef,$mtime,undef,undef,undef) = stat("$base/$entry");
		if (S_ISREG($mode) && ($mtime + $otp_window < $now)) {
			unlink "$base/$entry";
		}
	}
}

sub get_otp_serial($$) {
	-d $base || mkdir ($base, 0700);

	my $user = $_[0];
	my $remote_ip = $_[1];
	my $expires = undef;
	my $hash = undef;
	my $serial = undef;
	my $secret = undef;

	my $file = "$base/" . md5_hex($user) . md5_hex($remote_ip);

	my $F;
	if (open $F, $file) {
		my $in;
		foreach $in (split(/\n/, <$F>)) {
			if ($in =~ /^expires=(\d+)$/) {
				$expires = $1;
				next;
			}
			if ($in =~ /^hash=(.*)$/) {
				$hash = $1;
				next;
			}
			if ($in =~ /^serial=(.*)$/) {
				$serial = $1;
				next;
			}
		}
		close $F;
		if (defined($expires) && ($expires >= time) && defined($serial)){
			return $serial;
		}
	}

	$serial = strftime "%Y%m%d%H%M%S", localtime;
	$secret = sprintf("%.*d", $otp_len, int(rand(10**$otp_len)));
	$hash = md5_hex($secret);
	$expires = time + $otp_window;	# seconds

	if (sms_send($user, $serial, $secret)) {
		open ($F, ">$file") || die;
		print $F "serial=$serial\nhash=$hash\nexpires=$expires\n";
		close $F;
	}

	return $serial;
}

sub sms_challenge($$){
	return "SMS serial is " . get_otp_serial($_[0], $_[1]);
}

sub sms_verify($$$){
	my $user = $_[0];
	my $pin = $_[1];
	my $remote_ip = $_[2];
	my $expires = undef;
	my $hash = undef;

	if (defined($pin)) {
		my $file = "$base/" . md5_hex($user) . md5_hex($remote_ip);
		my $F;
		if (open $F, $file) {
			my $in;
			foreach $in (split(/\n/, <$F>)) {
				if ($in =~ /^expires=(\d+)$/) {
					$expires = $1;
					next;
				}
				if ($in =~ /^hash=(.*)$/) {
					$hash = $1;
					next;
				}
			}
			close $F;
			if (defined($expires) && ($expires >= time) && defined($hash) &&
				(md5_hex($pin) eq $hash)){
				return 0;
			}
		}
	}
	return 1;
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
	else {
		my $name = $V[AV_A_USER];

		if ($V[AV_A_TACTYPE] eq AV_V_TACTYPE_AUTH) {
			$V[AV_A_PASSWORD] =~ /^(\d{$otp_len})(.*)$/;

			my ($pin, $secret);
			$pin = $1;
			$secret = $2;
			if (!defined($pin) || sms_verify($name, $pin, $V[AV_A_IPADDR])) {
				$V[AV_A_USER_RESPONSE] = "Permission denied.";
				$V[AV_A_RESULT] = AV_V_RESULT_FAIL;
				$result = MAVIS_FINAL;
		    } else {
				$V[AV_A_RESULT] = AV_V_RESULT_OK;
				$V[AV_A_PASSWORD] = $secret;
				$result = MAVIS_DOWN;
		    }
		} elsif ($V[AV_A_TACTYPE] eq AV_V_TACTYPE_INFO){
			$result = MAVIS_DOWN;
		} elsif ($V[AV_A_TACTYPE] eq AV_V_TACTYPE_CHAL){
			$V[AV_A_CHALLENGE] = sms_challenge($name, $V[AV_A_IPADDR]);
			$V[AV_A_RESULT] = AV_V_RESULT_OK;
			$result = MAVIS_FINAL;
		} else {
		    $V[AV_A_USER_RESPONSE] = "Not implemented.";
			$V[AV_A_RESULT] = AV_V_RESULT_FAIL;
			$result = MAVIS_FINAL;
		}
	}

	my ($out) = "";
	for (my $i = 0; $i <= $#V; $i++) {
		$out .= sprintf ("%d %s\n", $i, $V[$i]) if defined $V[$i];
	}
	$out .= sprintf ("=%d\n", $result);
	print $out;

	$cleanup_count++;
	cleanup() unless $cleanup_count & 0x7F;
}

cleanup();

# vim: ts=4
