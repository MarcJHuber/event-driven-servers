#!/usr/bin/perl -w
#
# tac_akc.pl
# (C) 2022 by Marc Huber <Marc.Huber@web.de>
#
# Sample AuthorizedKeysCommand OpenSSH script for key lookup via tac_plus-ng.
# This is a PoC only.
#
# Usage: tac_akc.pl [options] <user> <fingerprint>
#
# Suitable sshd_config snippet:
#  AuthorizedKeysCommand /where/ever/tac_akc.pl %u %f
#  AuthorizedKeysCommandUser whoever
#
# Suitable tac_plus-ng configuration snippet:
#  user demo {
#     ...
#        ssh-key = "ssh-rsa YourPublicRSAKeyInBase64Endcoding="
#     ...
# }
#

my $version = '$Id$';

our $key = "demo";
our $host = "127.0.0.1";
our $port = 49;
my $rem_addr = ""; # not exposed by OpenSSH
my $rem_port = ""; # not exposed by OpenSSH

use Net::TacacsPlus::Client;
use Net::TacacsPlus::Constants;
use Net::TacacsPlus::Packet;
use Getopt::Long;

sub help {
	print <<EOT
Sample AuthorizedKeysCommand OpenSSH script for key lookup via tac_plus-ng.

Usage: $0 [ <Options> ] <user> <fingerprint>

Options:
  --help		show this text
  --defaults=<file>	read default settings from <file>, where <file>
                        is a valid Perl script. Example:
			  our \$key = "demo";
                          our \$host = "127.0.0.1";
                          our \$port = 49;
                          1;

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
) or help();

my ($username, $fingerprint)  = @ARGV;
my $tac = new Net::TacacsPlus::Client(host => $host, port => $port, key => $key);
$tac->init_tacacs_session();

my $pkt = Net::TacacsPlus::Packet->new(
	'type' => 1,
	'seq_no' => 1,
	'session_id' => int rand 0xffffffff,
 	'authen_method' => 6, # T+
	'authen_type' => 8, # TAC_PLUS_AUTHEN_TYPE_SSHKEY
	'user' => $username,
	'key' => $key,
	'rem_addr' => $rem_addr,
	'port' => $rem_port,
	'authen_service' => 1, # Login
	'action' => 1,
	'data' => $fingerprint,
	'minor_version' => 1
);
$pkt->send($tac->tacacsserver);

my $reply = $tac->recv_reply(TAC_PLUS_AUTHEN);
Net::TacacsPlus::Packet->check_reply($pkt, $reply);
print $reply->body->{'data'}, "\n" if $reply->status() == TAC_PLUS_AUTHEN_STATUS_PASS;

exit 0;
