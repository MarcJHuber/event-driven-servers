#!/usr/bin/env perl
# tacspooflog.pl
# (C) 2011-2023 by Marc Huber (Marc.Huber@web.de)
# License: BSD
# $Id$

# The Net::Frame code used below is based on
# https://metacpan.org/release/GOMOR/Net-Frame-1.21/source/examples/send-recv-udp.pl

use strict;

use Net::Write::Layer qw(:constants);
use Net::Write::Layer3;
use Net::Frame::Simple;
use Net::Frame::Layer::IPv4 qw(:consts);
use Net::Frame::Layer::IPv6 qw(:consts);
use Net::Frame::Layer::UDP;

use Sys::Syslog qw(:macros); 
use Getopt::Std;

my (%opts);
$opts{'l'} = "LOG_INFO";
$opts{'f'} = "LOG_AUTH";
$opts{'i'} = "tac_plus";

my $cmdline = join (' ', @ARGV);

getopts('l:f:i:I:R:D:4:6:d', \%opts);

my $prefix = '<' . int (eval "$opts{'f'} | $opts{'l'}") . ">" . $opts{'i'};

my ($daddr4, $daddr6) = @ARGV;
$daddr4 = $opts{'4'} if exists $opts{'4'};
$daddr6 = $opts{'6'} if exists $opts{'6'};

die "Usage: $0 [ Options ] [ <dst-ip4> [ <dst-ip6> ] ]

Options:
-4 <ip4-addr> IPv4 destination, overrides <dst-ip4>
-6 <ip6-addr> IPv6 destination, overrides <dst-ip6>
-f <facility> syslog facility                 [LOG_AUTH]
-l <level>    syslog priority                 [LOG_INFO]
-i <ident>    syslog ident                    [tac_plus]
-R <regex>    regex to determine IP and data  [^[^\\t]+\\t([^\\t]+)\\t(.*)\$]
-I <expr>     replacement expression for IP   [\$1]
-D <expr>     replacement expression for data [\$2]
-d            enable debug output for regex testing (don't use in production)

The R, I and D options are only evaluated if all three of them are set. The
purpose of these options is to support parsing of custom log formats.

Examples:
$0 -f LOG_AUTH -l LOG_INFO -i tac_plus 127.0.0.1
$0 -4 100.64.0.1 -6 '[fcff::1]:5140' -R '^(\S+)\s+(.*)\$' -I '\$1' -D '\$2'

" unless defined($daddr4) || defined ($daddr6);

my ($dport4, $dport6) = (514, 514);
if (defined $daddr4 && $daddr4 =~ /^([^:]+):(\d+)$/) {
	$daddr4 = $1;
	$dport4 = $2;
}
if (defined $daddr6) {
	if ($daddr6 =~ /^\[([^]]+)\]:(\d+)$/) {
		$daddr6 = $1;
		$dport6 = $2;
	} elsif ($daddr6 =~ /^\[([^]]+)\]$/) {
		$daddr6 = $1;
	}
}

if ($< > 0) {
	use POSIX qw(getcwd);
	my ($login) = getpwuid($<);
	my $me;
	if ($0 =~ /^\//) {
		$me = $0;
	} else {
		$me = getcwd() . "/$0";
		while ($me =~ s/\/\.\//\//g) {}
		while ($me =~ s/\/[^\/]+\/\.\.(\/.*)/$1/) {}
	}

	print <<EOT

This program needs to run as root. Consider adding a variant of

$login ALL = (root) NOPASSWD: $me

to /etc/sudoers, then try

  sudo $me $cmdline

EOT
;
	exit;
}

# customization options for use with tac_plus-ng:
my $R = exists $opts{'R'} ? $opts{'R'} : undef; # regex, e.g.: -R '^(\S+)\s+(.*)$'
my $I = exists $opts{'I'} ? $opts{'I'} : undef; # IP, e.g.:    -I '$1'
my $D = exists $opts{'D'} ? $opts{'D'} : undef; # data, e.g.:  -D '$2'
my $debug = exists $opts{'d'} ? $opts{'d'} : undef;
my $custom = defined($R) && defined($D) && defined($I);

my $in;
while ($in = <STDIN>) {
	chomp $in;
	my ($saddr, $data);
	if ($custom) {
		$in =~ /$R/;
		$saddr = eval $I;
		$data = eval $D;
	} else { # legacy default
		$in =~ /^[^\t]+\t([^\t]+)\t(.*)$/ or $in =~ /\s+(\S+):\s+(.*)$/ or next;
		$saddr = $1;
		$data = $2;
	}
	$data = "$prefix: $data";
	if ($debug) {
		print <<EOT
SOURCE: >>$saddr<<
SYSLOG: >>$data<<
EOT
		;
	}
	if ($saddr =~ /:/ && defined $daddr6) {
		my $ip = Net::Frame::Layer::IPv6->new(
			src		=> $saddr,
			dst		=> $daddr6,
			nextHeader	=> NF_IPv6_PROTOCOL_UDP,
		);
		my $udp = Net::Frame::Layer::UDP->new(
			dst		=> $dport6,
			payload		=> $data,
		);
		my $oWrite = Net::Write::Layer3->new(
			dst		=> $daddr6,
			family		=> NW_AF_INET6,
		);
		my $oSimple = Net::Frame::Simple->new(
			layers		=> [ $ip, $udp ],
		);
		$oWrite->open;
		$oSimple->send($oWrite);
		$oWrite->close;
	} elsif ($saddr !~ /:/ && defined $daddr4){
		my $ip = Net::Frame::Layer::IPv4->new(
			src		=> $saddr,
			dst		=> $daddr4,
			protocol	=> NF_IPv4_PROTOCOL_UDP,
		);
		my $udp = Net::Frame::Layer::UDP->new(
			dst		=> $dport4,
			payload		=> $data,
		);
		my $oWrite = Net::Write::Layer3->new(
			dst		=> $daddr4
		);
		my $oSimple = Net::Frame::Simple->new(
			layers		=> [ $ip, $udp ],
		);
		$oWrite->open;
		$oSimple->send($oWrite);
		$oWrite->close;
	}
}
