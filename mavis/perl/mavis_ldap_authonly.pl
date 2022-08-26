#!/usr/bin/env perl
# $Id$
#
# mavis_ldap_authonly.pl
# (C)2001-2010 Marc Huber <Marc.Huber@web.de>
# All rights reserved.
#
# Simple LDAP backend for libmavis_external.so
#

# Test input:
# 4 $USER
# 8 $PASS
# 49 AUTH
# =
#
# E.g.: printf "4 $USER\n8 $PASS\n49 AUTH\n=\n" | this_script.pl
#

use lib '/usr/local/lib/mavis/';
use lib '/Users/marc/DEVEL/PROJECTS/mavis/perl/'; # REMOVE #

use strict;
use Mavis;

my $LDAP_HOSTS	= ['ldap03', 'ldap04', 'ldap01', 'ldap02'];
my @LDAP_BIND = ();
my $LDAP_BASE	= 'ou=staff,dc=example,dc=com';
my $LDAP_SCOPE	= 'sub';
my $LDAP_FILTER	= '(uid=%s)';
my $use_tls = undef;
my $flag_cacheconn		= undef;

$flag_cacheconn			= $ENV{'FLAG_CACHE_CONNECTION'} if exists $ENV{'FLAG_CACHE_CONNECTION'};

if (exists $ENV{'LDAP_HOSTS'}) {
	$LDAP_HOSTS	= [];
	for my $h (split /\s+/, $ENV{'LDAP_HOSTS'}) {
		push @$LDAP_HOSTS, $h;
	}
}

$LDAP_SCOPE = $ENV{'LDAP_SCOPE'} if exists $ENV{'LDAP_SCOPE'};
$LDAP_BASE = $ENV{'LDAP_BASE'} if exists $ENV{'LDAP_BASE'};
$LDAP_FILTER = $ENV{'LDAP_FILTER'} if exists $ENV{'LDAP_FILTER'};
@LDAP_BIND = ($ENV{'LDAP_USER'}, password => $ENV{'LDAP_PASSWD'})
	if (exists $ENV{'LDAP_USER'} && exists $ENV{'LDAP_PASSWD'});
$use_tls = $ENV{'USE_TLS'} if exists $ENV{'USE_TLS'};

use Net::LDAP;
use Net::LDAP qw(LDAP_SUCCESS LDAP_SERVER_DOWN LDAP_TYPE_OR_VALUE_EXISTS
	LDAP_NO_SUCH_ATTRIBUTE LDAP_INVALID_CREDENTIALS LDAP_CONSTRAINT_VIOLATION);

if ((defined($use_tls) || ($ENV{'LDAP_HOSTS'} =~ /ldaps:/))
    && !eval("require IO::Socket::SSL")){
		print STDERR "Warning: IO::Socket::SSL.pm not found. Neither StartTLS nor LDAPS connections will work.\n";
}

$| = 1;

my ($in);

$/ = "\n=\n";

my $ldap = undef;

while ($in = <>) {
	my ($a, @V, $result);

	@V = ();
	$result = MAVIS_DEFERRED;

	chomp $in;

	foreach $a (split (/\n/, $in)) {
		next unless $a =~ /^(\d+) (.*)$/;
		$V[$1] = $2;
	}

	if (!defined $V[AV_A_USER]){
		$V[AV_A_USER_RESPONSE] = "User not set.";
		goto fatal;
	}
	if ($V[AV_A_USER] =~ /\(|\)|,|\||&|\*/){
		$V[AV_A_USER_RESPONSE] = "Username not valid.";
		goto fatal;
	}
	if (!defined $V[AV_A_PASSWORD]){
		$result = MAVIS_DOWN;
		goto bye;
	}

	if ($ldap) {
		# Cached LDAP connection still available?
		my $sock = $ldap->socket();
		if ($sock) {
			my ($rin, $ein) = (0, 0);
			vec($rin, fileno($sock), 1) = 1;
			vec($ein, fileno($sock), 1) = 1;
			if (0 < select($rin, undef, $ein, 0)) {
				$ldap->unbind;
				$ldap->disconnect;
				$ldap = undef;
			}
		} else {
			$ldap->unbind;
			$ldap->disconnect;
			$ldap = undef;
		}
	}

	my $retry;
	$retry = $ldap ? 1 : undef;

  retry_once:

	unless ($ldap) {
		$ldap = Net::LDAP->new($LDAP_HOSTS);
		unless ($ldap) {
			$V[AV_A_USER_RESPONSE] = "No answer from LDAP backend.";
			$V[AV_A_RESULT] = AV_V_RESULT_ERROR;
			$result = MAVIS_FINAL;
			goto bye;
		}
		if (defined $use_tls) {
			my $mesg = $ldap->start_tls;
			if ($mesg->code) {
				$V[AV_A_USER_RESPONSE] = "TLS negotiation failed.";
				goto fatal;
			}
		}
	}
	my $authdn = undef;
	my $mesg = $ldap->bind(@LDAP_BIND);
	if ($mesg->code && defined($retry)) {
		$retry = undef;
		$ldap->unbind;
		$ldap->disconnect;
		$ldap = undef;
		goto retry_once;
	}
	if ($mesg->code){
		$V[AV_A_USER_RESPONSE] = $mesg->error;
		goto fatal;
	}
	$mesg = $ldap->search(base=> $LDAP_BASE, filter => sprintf ($LDAP_FILTER, $V[AV_A_USER]),
						  scope => $LDAP_SCOPE, attrs => ['1.1']);
	if ($mesg->code){
		$V[AV_A_USER_RESPONSE] = $mesg->error;
		goto fatal;
	}
	foreach my $entry ($mesg->entries){
		$authdn = $entry->dn if (!defined $authdn) ||
			(length $entry->dn < length $authdn);
	}
	if ($authdn){
		my $mesg =  $ldap->bind($authdn, password =>
					$V[AV_A_PASSWORD]);
		if ($mesg->code) {
			$V[AV_A_USER_RESPONSE] = $mesg->error;
			$V[AV_A_RESULT] = AV_V_RESULT_ERROR;
			$V[AV_A_RESULT] = AV_V_RESULT_FAIL
				if ($mesg->code == LDAP_INVALID_CREDENTIALS || $mesg->code == LDAP_CONSTRAINT_VIOLATION);
			$result = MAVIS_FINAL;
			$ldap->unbind;
			$ldap->disconnect;
			$ldap = undef;
			goto bye;
		}

		$V[AV_A_DBPASSWORD] = $V[AV_A_PASSWORD];

		$V[AV_A_RESULT] = AV_V_RESULT_OK;
		$result = MAVIS_DOWN;
	} else {
		$V[AV_A_RESULT] = AV_V_RESULT_NOTFOUND;
		$result = MAVIS_DOWN;
	}

	goto bye;

fatal:
	$result = MAVIS_FINAL;
	$V[AV_A_RESULT] = AV_V_RESULT_ERROR;
	if (defined $ldap) {
		$ldap->unbind;
		$ldap->disconnect;
		$ldap = undef;
	}

bye:
	if (!defined($flag_cacheconn) && defined($ldap)) {
		$ldap->unbind;
		$ldap->disconnect;
		$ldap = undef;
	}
	my ($out) = "";
	for (my $i = 0; $i <= $#V; $i++) {
		$out .= sprintf ("%d %s\n", $i, $V[$i]) if defined $V[$i];
	}
	$out .= sprintf ("=%d\n", $result);
	print $out;
}

# vim: ts=4
