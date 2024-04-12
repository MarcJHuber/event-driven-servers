#!/usr/bin/env perl
# $Id$
#
# mavis_tacplus-ng_ldap2.pl
# (C)2001-2023 Marc Huber <Marc.Huber@web.de>
# All rights reserved.
#
# TACACS+ backend for libmavis_external.so
# Authenticates/authorizes against LDAP, optionally supports password changes.
# Suitable for tac_plus-ng only.
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

LDAP_HOSTS
	Space-separated list of LDAP URLs or IP addresses or hostnames
	Examples: "ldap01 ldap02", "ldaps://ads01:636 ldaps://ads02:636"

LDAP_SCOPE
	LDAP search scope (base, one, sub) for users
	Default: sub

LDAP_SCOPE_GROUP
	LDAP search scope (base, one, sub) for groups
	Default: sub

LDAP_BASE
	Base user search DN of your LDAP server
	Example: "dc=example,dc=com"

LDAP_BASE_GROUP
	Base groupe search DN of your LDAP server, defaults to LDAP_BASE
	Example: "dc=example,dc=com"

LDAP_CONNECT_TIMEOUT
	Timeout for initital connect to remote LDAP server. Default: 1 (second)

LDAP_FILTER
	LDAP search filter
	Defaults depend on LDAP_SERVER_TYPE:
	- generic:	"(&(objectclass=posixaccount)(uid=%s))"
	- microsoft:	"(&(objectclass=user)(sAMAccountName=%s))"

LDAP_FILTER_GROUP
	LDAP group search filter
	Default: "(&(objectclass=groupOfNames)(member=%s))"

LDAP_USER
	User to use for LDAP bind if server doesn't permit anonymous searches.
	Default: unset

LDAP_PASSWD
	Password for LDAP_USER
	Default: unset

LDAP_MEMBEROF_REGEX
	Regular expression to derive group names from memberOf
	Default: "^cn=([^,]+),.*"

LDAP_TACMEMBER
	LDAP attribute to use for group membership (fallback only).
	Default: "tacMember"

LDAP_TACMEMBER_MAP_OU
	Map organizational units from user DN to group membership.
	Default: unset

USE_STARTTLS
	If set, the server is required to support start_tls. Do not use this for plain LDAPS.
	Default: unset

FLAG_FALLTHROUGH
	If LDAP search fails, try next module (if any). Deprecated.
	Default: unset

FLAG_AUTHORIZE_ONLY
	Don't attempt to authenticate users.

TLS_OPTIONS
	Extra options for use with LDAPS or start_tls, in Perl hash syntax.
	See https://metacpan.org/pod/Net::LDAP for details.
	Default: unset
	Example: "sslversion => 'tlsv1_2'"
=cut

use lib '/usr/local/lib/mavis/';

use strict;
use Mavis;

my $LDAP_SERVER_TYPE;
my @LDAP_BIND;
my $LDAP_FILTER;
my $LDAP_FILTER_GROUP = "(&(objectclass=groupOfNames)(member=%s))";
my @LDAP_HOSTS		= ('https://localhost');
my $LDAP_BASE		= 'dc=example,dc=com';
my $LDAP_BASE_GROUP	= undef;
my $LDAP_CONNECT_TIMEOUT = 1;
my $LDAP_SCOPE		= 'sub';
my $LDAP_SCOPE_GROUP	= undef;
my $LDAP_MEMBEROF_REGEX = "^cn=([^,]+),.*";
my $LDAP_TACMEMBER	= "tacMember";
my $LDAP_TACMEMBER_MAP_OU	= undef;
my $use_starttls;
my %tls_options;

%tls_options = eval $ENV{'TLS_OPTIONS'} if exists $ENV{'TLS_OPTIONS'};

@LDAP_HOSTS		= split /\s+/, $ENV{'LDAP_HOSTS'} if exists $ENV{'LDAP_HOSTS'};
$LDAP_SCOPE		= $ENV{'LDAP_SCOPE'} if exists $ENV{'LDAP_SCOPE'};
$LDAP_BASE		= $ENV{'LDAP_BASE'} if exists $ENV{'LDAP_BASE'};
$LDAP_SCOPE_GROUP	= $LDAP_SCOPE;
$LDAP_BASE_GROUP	= $LDAP_BASE;
$LDAP_SCOPE_GROUP	= $ENV{'LDAP_SCOPE_GROUP'} if exists $ENV{'LDAP_SCOPE_GROUP'};
$LDAP_FILTER_GROUP	= $ENV{'LDAP_FILTER_GROUP'} if exists $ENV{'LDAP_FILTER_GROUP'};
$LDAP_BASE_GROUP	= $ENV{'LDAP_BASE_GROUP'} if exists $ENV{'LDAP_BASE_GROUP'};
$LDAP_FILTER		= $ENV{'LDAP_FILTER'} if exists $ENV{'LDAP_FILTER'};
$LDAP_CONNECT_TIMEOUT	= $ENV{'LDAP_CONNECT_TIMEOUT'} if exists $ENV{'LDAP_CONNECT_TIMEOUT'};
@LDAP_BIND		= ($ENV{'LDAP_USER'}, password => $ENV{'LDAP_PASSWD'}) if (exists $ENV{'LDAP_USER'} && exists $ENV{'LDAP_PASSWD'});
$use_starttls		= $ENV{'USE_STARTTLS'} if exists $ENV{'USE_STARTTLS'};
$LDAP_MEMBEROF_REGEX	= $ENV{'LDAP_MEMBEROF_REGEX'} if exists $ENV{'LDAP_MEMBEROF_REGEX'};
$LDAP_TACMEMBER		= $ENV{'LDAP_TACMEMBER'} if exists $ENV{'LDAP_TACMEMBER'};
$LDAP_TACMEMBER_MAP_OU	= $ENV{'LDAP_TACMEMBER_MAP_OU'} if exists $ENV{'LDAP_TACMEMBER_MAP_OU'};

use Net::LDAP qw(LDAP_INVALID_CREDENTIALS LDAP_CONSTRAINT_VIOLATION);
use Net::LDAP::Constant qw(LDAP_EXTENSION_PASSWORD_MODIFY LDAP_CAP_ACTIVE_DIRECTORY);
use Net::LDAP::Extension::SetPassword;
use Net::LDAP::Extra qw(AD);
use IO::Socket::SSL;
use POSIX qw(mktime);

$| = 1;

my $in;
my $has_extension_password_modify;

$/ = "\n=\n";

my $ldap = undef;

my @V;

sub expand_groupOfNames($) {
	my %H;
	sub expand_groupOfNames_sub($) {
		sub get_groupOfNames($) {
			my $dn = $_[0];
			my @res = ( );
			my $mesg = $ldap->search(base => $LDAP_BASE_GROUP, scope=>$LDAP_SCOPE_GROUP, filter=>sprintf($LDAP_FILTER_GROUP, $dn), attrs=>['memberOf']);
			if ($mesg->code){
				$V[AV_A_USER_RESPONSE] = $mesg->error . " (" . __LINE__ . ")";
				goto fatal;
			}
			foreach my $entry ($mesg->entries) {
				push @res, $entry->dn unless exists $H{$entry->dn};
			}
			return @res;
		}
		sub expand_groupOfNames_sub($);

		foreach my $g (get_groupOfNames($_[0])) {
			unless (exists $H{$g}) {
				$H{$g} = 1;
				expand_groupOfNames_sub($g);
			}
		}
	}
	expand_groupOfNames_sub($_[0]);
	my @res = sort keys %H;
	return \@res;
}

sub expand_memberof($) {
	sub expand_memberof_sub($$) {
		sub get_memberof($) {
			my $mesg = $ldap->search(base => $_[0], scope=>'base', filter=>'(objectclass=*)', attrs=>['memberOf']);
			if ($mesg->code){
				$V[AV_A_USER_RESPONSE] = $mesg->error . " (" . __LINE__ . ")";
				goto fatal;
			}
			my $entry = $mesg->entry(0);
			return $entry->get_value('memberOf', asref => 1) if $entry;
			return [ ];
		}
		sub expand_memberof_sub($$);

		my ($a, $H) = @_;
		foreach my $m (@$a) {
			unless (exists $H->{$m}) {
				$H->{$m} = 1;
				my $g = get_memberof($m);
				expand_memberof_sub($g, $H);
			}
		}
	}

	my %H;
	expand_memberof_sub($_[0], \%H);
	my @res = sort keys %H;
	return \@res;
}

while ($in = <>) {
	my ($a, $result);

	@V = ();
	$result = MAVIS_DEFERRED;

	chomp $in;

	foreach $a (split (/\n/, $in)) {
		next unless $a =~ /^(\d+) (.*)$/;
		$V[$1] = $2;
	}

	if (defined $V[AV_A_TYPE] && $V[AV_A_TYPE] ne AV_V_TYPE_TACPLUS) {
		$result = MAVIS_DOWN;
		goto bye;
	}
	if (!defined $V[AV_A_USER]){
		$V[AV_A_USER_RESPONSE] = "User not set.";
		goto fatal;
	}
	if ($V[AV_A_USER] =~ /\(|\)|,|\||&|=|\*/){
		$V[AV_A_USER_RESPONSE] = "Username not valid.";
		goto fatal;
	}
	if ($V[AV_A_TACTYPE] eq AV_V_TACTYPE_AUTH && !defined $V[AV_A_PASSWORD]){
		$V[AV_A_USER_RESPONSE] = "Password not set.";
		goto fatal;
	}
	if ($V[AV_A_TACTYPE] eq AV_V_TACTYPE_CHPW && (!defined $V[AV_A_PASSWORD]||!defined $V[AV_A_PASSWORD_NEW])){
		$V[AV_A_USER_RESPONSE] = "Old or new password not set";
		goto fatal;
	}

	if ($ldap) {
# Cached LDAP connection still available?
		my $sock = $ldap->socket();
		if ($sock) {
			my ($rin, $ein) = (0, 0);
			vec($rin, fileno($sock), 1) = 1;
			vec($ein, fileno($sock), 1) = 1;
			if (0 < select($rin, undef, $ein, 0)) {
				printf STDERR "ldap connection detected dead (" . __LINE__ . ")\n";
				$ldap->unbind;
				$ldap->disconnect;
				$ldap = undef;
			}
		} else {
			printf STDERR "ldap connection dead (" . __LINE__ . ")\n";
			$ldap->unbind;
			$ldap->disconnect;
			$ldap = undef;
		}
	}

	my $retry;
	$retry = $ldap ? 1 : undef;

retry_once:

	unless ($ldap) {
		$ldap = Net::LDAP->new(\@LDAP_HOSTS, timeout=>$LDAP_CONNECT_TIMEOUT, %tls_options);
		unless ($ldap) {
			$V[AV_A_USER_RESPONSE] = "No answer from LDAP backend.";
			goto fatal;
		}
		if (defined $use_starttls) {
			my $mesg = $ldap->start_tls(%tls_options);
			if ($mesg->code) {
				$V[AV_A_USER_RESPONSE] = "TLS negotiation failed.";
				goto fatal;
			}
		}
		unless (defined $LDAP_SERVER_TYPE) {
			if ($ldap->is_AD() || $ldap->is_ADAM()) {
				$LDAP_SERVER_TYPE = "microsoft";
				$LDAP_FILTER = '(&(objectclass=user)(sAMAccountName=%s))' unless defined $LDAP_FILTER;
			} else {
				$LDAP_SERVER_TYPE = "generic";
				$LDAP_FILTER = '(&(objectclass=posixAccount)(uid=%s))' unless defined $LDAP_FILTER;
			}
		}
		my $vendor = $ldap->root_dse->get_value('vendorname');
		if (defined($vendor) && $vendor =~ /389 Project/ && $#LDAP_BIND < 0) {
			printf STDERR "The 389 directory server will not return the memberOf attribute for anonymous binds. " .
				      "Please set the LDAP_USER and LDAP_PASSWD environment variables.\n";
		}
	}

	my $authdn = undef;
	my $mesg = $ldap->bind(@LDAP_BIND);
	if ($mesg->code && defined($retry)) {
		$retry = undef;
		$ldap->unbind;
		$ldap->disconnect;
		$ldap = undef;
		printf STDERR "ldap retry, due to bind failure (" . __LINE__ . ")\n";
		goto retry_once;
	}
	if ($mesg->code){
		$V[AV_A_USER_RESPONSE] = $mesg->error . " (" . __LINE__ . ")";
		goto fatal;
	}
	unless (defined $has_extension_password_modify) {
		$has_extension_password_modify =
			$ldap->root_dse->supported_extension(LDAP_EXTENSION_PASSWORD_MODIFY);
	}
	$mesg = $ldap->search(base => $LDAP_BASE, filter => sprintf($LDAP_FILTER, $V[AV_A_USER]), scope => $LDAP_SCOPE,
		attrs => ['shadowExpire','memberOf','dn', 'uidNumber', 'gidNumber', 'loginShell', 'homeDirectory', 'sshPublicKey',
			  'krbPasswordExpiration', $LDAP_TACMEMBER]);
	if ($mesg->count() == 1) {
		my $entry = $mesg->entry(0);

		my $val = $entry->get_value('memberOf', asref => 1);
		$authdn = $entry->dn;
		my (@M, @MO);
		if ($#{$val} > -1) {
			$val = expand_memberof($val);
		} else {
			$val = expand_groupOfNames($entry->dn);
		}
		foreach my $m (sort @$val) {
			if ($m =~ /$LDAP_MEMBEROF_REGEX/i) {
				push @M, $1;
				push @MO, $m;
			}
		}
		$V[AV_A_TACMEMBER] = '"' . join('","', @M) . '"' if $#M > -1;
		$V[AV_A_MEMBEROF] = '"' . join('","', @MO) . '"' if $#MO > -1;
		$V[AV_A_DN] = $authdn;
		$V[AV_A_UID] = $val if $val = $entry->get_value('uidNumber');
		$V[AV_A_GID] = $val if $val = $entry->get_value('gidNumber');
		$V[AV_A_SHELL] = $val if $val = $entry->get_value('loginShell');
		$V[AV_A_HOME] = $val if $val = $entry->get_value('homeDirectory');
		$V[AV_A_SSHKEY] = $val if $val = $entry->get_value('sshPublicKey');
		my $authdn = $mesg->entry(0)->dn;

		unless (exists($V[AV_A_MEMBEROF])) {
			$val = $entry->get_value($LDAP_TACMEMBER, asref => 1);
			$V[AV_A_MEMBEROF] = '"' . join('","', @$val) . '"' if $#{$val} > -1;
		}

		if (defined $LDAP_TACMEMBER_MAP_OU) {
			for my $ou (split(/,/, $authdn)) {
				next unless $ou =~ /^ou=(.+)$/i;
				if (exists ($V[AV_A_TACMEMBER])) {
					$V[AV_A_TACMEMBER] .= ",\"$1\"";
				} else {
					$V[AV_A_TACMEMBER] = "\"$1\"";
				}
			}
		}

		if ($V[AV_A_TACTYPE] eq AV_V_TACTYPE_AUTH) {
			my $caller_cap_chpw = exists($V[AV_A_CALLER_CAP]) && $V[AV_A_CALLER_CAP] =~ /:chpw:/;
			my $expiry = undef;
			$val = $entry->get_value('shadowExpire');
			if (defined $val) {
				$expiry = 86400 * $val if $val > -1;
			} else {
				$val = $entry->get_value('krbPasswordExpiration');
				if (defined $val) {
					if ($val =~ /^(\d\d\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)Z$/) {
						$expiry = mktime($6, $5, $4, $3, $2 - 1, $1 - 1900);
					}
				}
			}
			if (defined $expiry) {
				if ($expiry < time) {
					$V[AV_A_USER_RESPONSE] = "Password has expired.";
					if ($caller_cap_chpw && $has_extension_password_modify) {
						$V[AV_A_PASSWORD_MUSTCHANGE] = 1;
					} else {
						goto fail;
					}
				} else {
					$V[AV_A_PASSWORD_EXPIRY] = $expiry;
				}
			}
			$mesg =  $ldap->bind($authdn, password => $V[AV_A_PASSWORD]);
			my $code = $mesg->code;
			my $userresponse = undef;
			if ($code == LDAP_INVALID_CREDENTIALS && $LDAP_SERVER_TYPE eq 'microsoft') {
				my %ad_error_codes = (
					"525" => "Invalid credentials.", # "User not found.", actually
					"52e" => "Invalid credentials.",
					"530" => "Not permitted to logon at this time.",
					"531" => "Not permitted to logon at this workstation.",
					"532" => "Password expired.",
					"533" => "Account disabled.",
					"701" => "Account expired.",
					"773" => "User must reset password.",
					"775" => "User account locked.",
				);
				my $m = $mesg->error;
				$m =~ s/.*DSID-.*, data ([0-9A-Fa-f]+),.*/$1/;
				if($caller_cap_chpw && ($m eq "532" || $m eq "533" || $m eq "773")) {
					$code = 0;
					$V[AV_A_PASSWORD_MUSTCHANGE] = 1;
				} elsif (exists $ad_error_codes{$m}) {
					$userresponse = $ad_error_codes{$m};
				}
			}
			if ($code) {
				$userresponse = $mesg->error unless defined $userresponse;
				$V[AV_A_USER_RESPONSE] = $userresponse;
				goto fail if $mesg->code == LDAP_INVALID_CREDENTIALS || $mesg->code == LDAP_CONSTRAINT_VIOLATION;
				goto fatal;
			}
			$V[AV_A_RESULT] = AV_V_RESULT_OK;
			$V[AV_A_PASSWORD_ONESHOT] = "1";
		} elsif ($V[AV_A_TACTYPE] eq AV_V_TACTYPE_CHPW){
			if ($LDAP_SERVER_TYPE eq 'microsoft') {
				$mesg = $ldap->change_ADpassword($authdn, $V[AV_A_PASSWORD], $V[AV_A_PASSWORD_NEW]);
			} else {
				unless (defined($has_extension_password_modify)) {
					$V[AV_A_USER_RESPONSE] = "Password change is unsupported.";
					goto fail;
				}
				$mesg =  $ldap->bind($authdn, password => $V[AV_A_PASSWORD]);
				if ($mesg->code) {
					$V[AV_A_USER_RESPONSE] = $mesg->error . " (" . __LINE__ . ")";
					goto fail if ($mesg->code == LDAP_INVALID_CREDENTIALS || $mesg->code == LDAP_CONSTRAINT_VIOLATION);
					goto fatal;
				}

				if ($has_extension_password_modify) {
					$mesg = $ldap->set_password(oldpasswd => $V[AV_A_PASSWORD], newpasswd => $V[AV_A_PASSWORD_NEW]);
				} else {
					$V[AV_A_USER_RESPONSE] = "LDAP server doesn't support password modifications.";
					goto fail;
				}
			}

			if ($mesg->code){
				if ($mesg->error =~ /CONSTRAINT_ATT_TYPE/s) {
					$V[AV_A_USER_RESPONSE] = "Password change rejected by policy.";
				} else {
					$V[AV_A_USER_RESPONSE] = $mesg->error;
				}
				print STDERR "chpw for ", $authdn, ": ", $mesg->error, " (" , __LINE__ , ")", "\n";
				goto fail;
			}
			delete $V[AV_A_PASSWORD_MUSTCHANGE];
			$V[AV_A_USER_RESPONSE] = "Password change was successful.";
			$V[AV_A_PASSWORD_ONESHOT] = "1";
			$V[AV_A_RESULT] = AV_V_RESULT_OK;
		} elsif ($V[AV_A_TACTYPE] eq AV_V_TACTYPE_INFO){
			$V[AV_A_RESULT] = AV_V_RESULT_OK;
		}
		$result = MAVIS_FINAL;
		goto bye;
	} else {
		goto down;
	}

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
