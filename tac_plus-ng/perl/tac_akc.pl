#!/usr/bin/perl -w
#
# tac_akc.pl
# (C) 2022 by Marc Huber <Marc.Huber@web.de>
#
# Sample AuthorizedKeysCommand OpenSSH script for key lookup via tac_plus-ng. This is a PoC only
# and requires that tac_plus-ng is a compiled with #define TPNG_EXPERIMENTAL in headers.h
#
# Usage: tac_akc.pl <user> <fingerprint>
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


my $key = "demo";
my $host = "172.16.0.238";
my $port = 4949;
my $username = $ARGV[0];
my $password = $ARGV[1]; # the fingerprint, actually
my $rem_addr = ""; # not exposed by OpenSSH
my $rem_port = ""; # not exposed by OpenSSH

use Net::TacacsPlus::Client;
use Net::TacacsPlus::Constants;
use Net::TacacsPlus::Packet;

my $tac = new Net::TacacsPlus::Client(host => $host, port => $port, key => $key);

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
	'data' => $password,
	'minor_version' => 1
);

$tac->init_tacacs_session();
$pkt->send($tac->tacacsserver);
my $reply = $tac->recv_reply(TAC_PLUS_AUTHEN);
Net::TacacsPlus::Packet->check_reply($pkt, $reply);
if ($reply->status() == TAC_PLUS_AUTHEN_STATUS_PASS) {
	print $reply->body->{'data'}, "\n";
}
exit 0;


