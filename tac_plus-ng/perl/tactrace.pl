#!/usr/bin/perl -w
#
# tactrace.pl
# (C) 2022 by Marc Huber <Marc.Huber@web.de>
#

use POSIX;
use Socket;
use Net::IP;
use Net::TacacsPlus::Packet;
use Getopt::Long;
use Scm; # This is from spawnd/perl/ ...

my $version = '$Id$';

# Defaults. Can be overridden with --defaults=<file>
# E.g.
# # cat ./defaults.pl
# our username = "demo";
# 1; # <- this is mandatory
# #
our $username = $ENV{"USER"};
our $port = "vty0";
our $remote = "127.0.0.1";
our $key = "demo";
our $realm = "default";
our $nad = "127.0.0.1";
our $authentype = 1;
our $authenmethod = 1;
our $exec = "/usr/local/sbin/tac_plus-ng";
our $conf = "/usr/local/etc/tac_plus-ng.cfg";
our $id = "tac_plus-ng";
our @args = ( "service=shell", "cmd*" );

sub help {
	my $arglist = '"' . join('" "', @args) . '"';
	print <<EOT
This is a TACACS+ authorization validator for $id.

Usage: $0 [ <Options> ] [ <attributes> ... ]

<attributes are the autorization AV pairs, default is:
	$arglist

Options:
  --help		show this text
  --defaults=<file>	read default settings from <file>
  --username=<username> username [$username]
  --port=<port>		port [$port]
  --remote=<client ip>	remote client ip [$remote]
  --key=<key>		encryption key [$key]
  --realm=<realm>	realm [$realm]
  --nad=<address>	NAD (router/switch/...) IP address [$nad]
  --authentype=<n>	authen_type [$authentype]
  --authenmethod=<n>	authen_method [$authenmethod]
  --exec=<path>		executable path [$exec]
  --conf=<config>	configuration file [$conf]
  --id=<id>		id for configuration selection [$id]

Version: $version

Copyright (C) 2022 by Marc Huber <Marc.Huber\@web.de>

Source code and documentation: http://www.pro-bono-publico.de/projects/

Please direct support requests either to the "Event-Driven Servers" Google Group at

    event-driven-servers\@googlegroups.com
    http://groups.google.com/group/event-driven-servers

or open an issue at the GitHub page at

    https://github.com/MarcJHuber/event-driven-servers/issues

Support requests sent to the author's private email address may be silently ignored.
EOT
	;
	exit(0);
};

sub read_defaults {
	my ($a, $v) = @_;
	require $v or die "require: $!";
}

GetOptions (
	"help"		=> \&help,
	"defaults=s"	=> \&read_defaults,
	"username=s"	=> \$username,
	"port=s"	=> \$port,
	"remote=s"	=> \$remote,
	"key=s"		=> \$key,
	"realm=s"	=> \$realm,
	"nad=s"		=> \$nad,
	"authentype=i"	=> \$authentype,
	"authenmethod=i"=> \$authenmethod,
	"exec=s"	=> \$exec,
	"conf=s"	=> \$conf,
	"id=s"		=> \$id
) or help();

@args = @ARGV if $#ARGV > -1;

die "Can't access $conf" unless -r "$conf";

# start tac_plus-ng:
my($sock0, $sock1);
socketpair($sock0, $sock1, AF_UNIX, SOCK_DGRAM, PF_UNIX) or die "socketpair: $!";
$sock0->autoflush(1);
$sock1->autoflush(1);
my $pid = fork();
die "fork: $!" if $pid < 0;
if ($pid == 0) {
	close $sock0;
	POSIX::dup2 (fileno $sock1, 0) or die "POSIX::dup2: $!";
	close $sock1;
	exec($exec, "-d", "546", "-d", "4194304", $conf, $id);
	die "exec: $!";;
}
close $sock1;

# create a socket pair for packet injection and send the second fd to tac_plus-ng:
my($conn0, $conn1);
socketpair($conn0, $conn1, AF_UNIX, SOCK_STREAM, PF_UNIX) or die "socketpair: $!";
Scm::scm_sendmsg_accept(fileno $sock0, 6, fileno $conn1, 1, $realm);

# create a haproxy v2 header for NAD address simulation:
my $src = new Net::IP($nad) or die Net::IP::Error();
my $hexip = $src->hexip();
$hexip =~ s/^0x//;
my ($pad, $fam, $famlen) = (8, 0x11, 12);
($pad, $fam, $famlen) = (20, 0x21, 36) if $src->version == 6;
my $phdr = pack('W' x 16 . 'h*' . 'W' x $pad,
	0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, 0x20, 
	$fam, $famlen >> 8, $famlen & 0xff, $hexip, 0 x $pad);
syswrite($conn0, $phdr, 16 + $famlen) or die "syswrite: $!";;

# create a TACACS+ authorization packet and send it to tac_plus-ng:
my $pkt = Net::TacacsPlus::Packet->new(
	'type' => 2,
	'seq_no' => 1,
	'session_id' => 1,
 	'authen_method' => $authenmethod,
	'authen_type' => $authentype,
	'user' => $username,
	'args' => \@args,
	'key' => $key,
	'remote' => $remote,
	'port' => $port,
);
my $raw = $pkt->raw();
syswrite($conn0, $raw, length($raw)) or die;
sysread($conn0, my $buf, my $len = 1);
exit 0;
