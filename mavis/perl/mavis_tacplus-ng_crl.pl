#!/usr/bin/env perl
# $Id$
#
# mavis_tacplus-ng_crl.pl
# (C)2025 Marc Huber <Marc.Huber@web.de>
# All rights reserved.
#
# MAVIS backend for checking CRL status, suitable for tac_plus-ng only.
#
# Requires initialization and regular updates with --update ...
#

=pod

  # Usage:

  mavis module = external {
        exec = ../../mavis/perl/mavis_tacplus-ng_crl.pl mavis_tacplus-ng_crl.pl "--basedir=/var/tac_plus-ng/crl"
        script out {
                if ($TYPE == "TACPLUS" && $TACTYPE == "HOST" && !defined $RESULT) {
                        set $RESULT = "ACK"
                        return
                }
        }
  }

  # or just:

  tls crl-dir = /var/tac_plus-ng/crl

=cut

use lib '/usr/local/lib/mavis/';
use strict;
use Mavis;
use Getopt::Long;
use LWP::Simple;
use IPC::Open3;

$| = 1;

my $BASEDIR = "/tmp";
my $update = undef;
my $openssl = "/usr/bin/openssl";
my $ca = undef;

GetOptions(
	"basedir=s" => \$BASEDIR,
	"update" => \$update,
	"openssl=s" => \$update,
	"ca=s" => \$ca,
);

die "Usage: $0 [--basedir=<dir>] [ [--update [--openssl=<openssl_bin>] [--ca=<ca_cert_pem>] <crl_url> ]\n"
	if ($#ARGV != 0 && $update) || ($#ARGV > -1 && !$update);

if ($update) {
	my $der = get($ARGV[0]);
	die "Could not retrieve $ARGV[0]\n" unless defined $der;

	use Symbol 'gensym';
	if (defined $ca) {
		my $pid = open3(my $chld_in, my $chld_out, my $chld_err = gensym,
			$openssl, 'crl', '-inform', 'der', '-CAfile', $ca, '-noout');

		print $chld_in $der;
		close $chld_in;
		while (<$chld_out>) {
			print $_;
		}
		close $chld_out;
		while (<$chld_err>) {
			print STDERR $_;
		}
		close $chld_err;
		waitpid($pid, 0);
		my $child_exit_status = $? >> 8;
		die if $child_exit_status != 0
	}

	my $pid = open3(my $chld_in, my $chld_out, my $chld_err = gensym,
		$openssl, 'crl', '-inform', 'der', '-text', '-noout');

	print $chld_in $der;
	close $chld_in;

	my $aki = undef;
	my $dir = undef;

	while (<$chld_out>) {
		chomp;
		if (!defined($aki) && /X509v3 Authority Key Identifier:/) {
			$aki = lc <$chld_out>;
			$aki =~ s/\s+//g;
			$aki =~ s/://g;
			$dir = $aki;
			mkdir $BASEDIR, 0755;
			mkdir "$BASEDIR/$dir", 0755;
		} elsif (defined $dir && /Serial Number: ([0-9A-F]+)/) {
			my $serial = lc $1;
			my $T;
			open ($T, ">$BASEDIR/$dir/$serial") && close $T;
		}
	}
	close $chld_out;
	while (<$chld_err>) {
		print STDERR $_;
	}
	close $chld_err;
	waitpid($pid, 0);
	my $child_exit_status = $? >> 8;
	die if $child_exit_status != 0;

	exit 0;
}

$BASEDIR = $ENV{'BASEDIR'} if exists $ENV{'BASEDIR'};

my $in;

$/ = "\n=\n";

my @V;

while ($in = <>) {
	my ($a, $result);

	@V = ();
	$result = MAVIS_DOWN;

	chomp $in;

	foreach $a (split (/\n/, $in)) {
		next unless $a =~ /^(\d+) (.*)$/;
		$V[$1] = $2;
	}

	goto bye if (defined $V[AV_A_TYPE] && $V[AV_A_TYPE] ne AV_V_TYPE_TACPLUS);
	goto bye if ($V[AV_A_TACTYPE] ne AV_V_TACTYPE_HOST);
	goto bye if (!defined($V[AV_A_CERTDATA]));

	my $issuer = $V[AV_A_CERTDATA];
	unless ($issuer =~ s/^(.*,|)issueraki="([^"]+)".*$/$2/) {
		$issuer = $V[AV_A_CERTDATA];
		$issuer =~ s/^(.*,|)issuer="([^"]+)".*$/$2/ or goto bye;
		$issuer = md5_hex($issuer);
	}

	my $serial = $V[AV_A_CERTDATA];
	$serial =~ s/^(.*,|)serial="([^"]+)".*$/$2/ or goto bye;

	if (-f "$BASEDIR/$issuer/$serial") {
		$V[AV_A_RESULT] = AV_V_RESULT_FAIL;
		$result = MAVIS_FINAL;
		goto bye;
	}

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
