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
our $mode = "authz";
our $username = $ENV{"USER"};
our $password = $ENV{"TACTRACEPASSWORD"}; # No CLI option, don't want this to be visible via ps
our $port = "vty0";
our $remote = "127.0.0.1";
our $key = "demo";
our $realm = "default";
our $nad = "127.0.0.1";
our $authentype = "ascii";
our $authenmethod = "tacacsplus";
our $authenservice = "login";
our $exec = "/usr/local/sbin/tac_plus-ng";
our $conf = "/usr/local/etc/tac_plus-ng.cfg";
our $id = "tac_plus-ng";
our @args = ( "service=shell", "cmd*" );

sub help {
	my $arglist = '"' . join('" "', @args) . '"';
	print <<EOT
This is a TACACS+ AAA validator for $id.

Usage: $0 [ <Options> ] [ <attributes> ... ]

attributes are the autorization or accounting AV pairs, default is:
	$arglist

Options:
  --help		show this text
  --defaults=<file>	read default settings from <file>
  --mode=<mode>		authc, authz or acct [$mode]
  --username=<username> username [$username]
  --port=<port>		port [$port]
  --remote=<client ip>	remote client ip [$remote]
  --key=<key>		encryption key [$key]
  --realm=<realm>	realm [$realm]
  --nad=<address>	NAD (router/switch/...) IP address [$nad]
  --authentype=<type>	authen_type [$authentype]
  --authenmethod=<n>	authen_method [$authenmethod]
  --authenservice=<n>	authen_method [$authenservice]
  --exec=<path>		executable path [$exec]
  --conf=<config>	configuration file [$conf]
  --id=<id>		id for configuration selection [$id]

For authc the password can be set either via the environment variable
TACTRACEPASSWORD or the defaults file. Setting it via a CLI option isn't
supported as the password would show up as clear text in the process listing.

Version: $version

Copyright (C) 2022 by Marc Huber <Marc.Huber\@web.de>

Source code and documentation: http://www.pro-bono-publico.de/projects/

Please direct support requests either to the "Event-Driven Servers" Google
Group at

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
	"mode=s"	=> \$mode,
	"username=s"	=> \$username,
	"port=s"	=> \$port,
	"remote=s"	=> \$remote,
	"key=s"		=> \$key,
	"realm=s"	=> \$realm,
	"nad=s"		=> \$nad,
	"authentype=s"	=> \$authentype,
	"authenmethod=s"=> \$authenmethod,
	"authenservice=s"=> \$authenservice,
	"exec=s"	=> \$exec,
	"conf=s"	=> \$conf,
	"id=s"		=> \$id
) or help();

@args = @ARGV if $#ARGV > -1;

die "Can't access $conf" unless -r "$conf";

my %Mode = ( "authc" => 1, "authz" => 2, "acct" => 3 );
die "--mode=$mode unknown, supported args are " . join(", ", keys %Mode) unless exists $Mode{$mode};
my %Authentype = ( "ascii" => 1, "pap" => 2 );
die "--authentype=$authentype unknown, supported args are " . join(", ", keys %Authentype) unless exists $Authentype{$authentype};
my %Authenmethod = ( "none" => 1, "krb5" => 2, "line" => 3, "enable" => 4, "local" => 5, "tacacsplus" => 6, "guest" => 8, "radius" => 0x10, "krb4" => 0x11, "rcmd" => 0x20 );
die "--authenmethod=$authenmethod unknown, supported args are " . join(", ", keys %Authenmethod) unless exists $Authenmethod{$authenmethod};
my %Authenservice = ( "none" => 0, "login" => 1, "enable" => 2, "ppp" => 3, "pt"=> 5, "rcmd" => 6, "x25" => 7, "nasi" => 8 );
die "--authenservice=$authenservice unknown, supported args are " . join(", ", keys %Authenservice) unless exists $Authenservice{$authenservice};

# start tac_plus-ng:
socketpair(my $sock0, my $sock1, AF_UNIX, SOCK_DGRAM, PF_UNIX) or die "socketpair: $!";
$sock0->autoflush(1);
$sock1->autoflush(1);
my $pid = fork();
die "fork: $!" if $pid < 0;
if ($pid == 0) {
	close $sock0;
	POSIX::dup2 (fileno $sock1, 0) or die "POSIX::dup2: $!";
	close $sock1;
	exec($exec, "-d", "802", "-d", "4194304", $conf, $id);
	die "exec: $!";;
}
close $sock1;

# create a socket pair for packet injection and send the second fd to tac_plus-ng:
socketpair(my $conn0, my $conn1, AF_UNIX, SOCK_STREAM, PF_UNIX) or die "socketpair: $!";
Scm::scm_sendmsg_accept(fileno $sock0, 6, fileno $conn1, 1, $realm);

# create a haproxy v2 header for NAD address simulation:
my $src = new Net::IP($nad) or die Net::IP::Error();
my @binip = ($src->binip() =~ /(.{8})/g);
my ($pad, $fam, $famlen) = (8, 0x11, 12);
($pad, $fam, $famlen) = (20, 0x21, 36) if $src->version == 6;
my $phdr = pack('W' x 16 . 'B8' x ($#binip + 1) . 'W' x $pad,
	0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, 0x20, 
	$fam, $famlen >> 8, $famlen & 0xff, @binip, 0 x $pad);
syswrite($conn0, $phdr, 16 + $famlen) or die "syswrite: $!";;

# create a TACACS+ $mode packet and send it to tac_plus-ng:

my $pkt = Net::TacacsPlus::Packet->new(
	'type' => $Mode{$mode},
	'seq_no' => 1,
	'session_id' => 1,
 	'authen_method' => $Authenmethod{$authenmethod},
	'authen_type' => $Authentype{$authentype},
	'user' => $username,
	'args' => \@args,
	'key' => $key,
	'rem_addr' => $remote,
	'port' => $port,
	'authen_service' => $Authenservice{$authenservice},
	'action' => 1,
	'data' => $password,
	'minor_version' => ($authentype eq "pap" && $mode eq "authc") ? 1 : 0
);

my $raw = $pkt->raw();
syswrite($conn0, $raw, length($raw)) or die;
sysread($conn0, my $buf, my $len = 1);
exit 0;
