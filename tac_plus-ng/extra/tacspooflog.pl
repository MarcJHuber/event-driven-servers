#!/usr/bin/env perl
# tacspooflog.pl
# (C) 2011 by Marc Huber (Marc.Huber@web.de)
# License: BSD
# $Id$

use strict;

use Net::RawIP;
use Sys::Syslog qw(:macros); 
use Getopt::Std;

my (%opts);
$opts{'l'} = "LOG_INFO";
$opts{'f'} = "LOG_AUTH";
$opts{'i'} = "tac_plus";

my $cmdline = join (' ', @ARGV);

getopts('l:f:i:', \%opts);

my $prefix = '<' . int (eval "$opts{'f'} | $opts{'l'}") . ">" . $opts{'i'};

die
"Usage:   $0 [-f <facility>] [-l <level>] [-i <ident>] <dst-ip>\n" .
"Example: $0 -f LOG_AUTH -l LOG_INFO -i tac_plus 127.0.0.1\n"
unless $#ARGV == 0;

my ($daddr) = @ARGV;

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

my $in;
while ($in = <STDIN>) {
	chomp $in;
	$in =~ /^[^\t]+\t([^\t]+)\t(.*)$/ or $in =~ /\s+(\S+):\s+(.*)$/;
	my $saddr = $1; 
	my $data = $2;
	my $packet = new Net::RawIP({udp=>{}});
	$packet->set({ ip => { saddr => $saddr, daddr => $daddr },
		udp => { source => int rand(0xec00) + 0x400,
			 dest => 514, data=>"$prefix: $data" }
	});
	$packet->send;
}
