#!/usr/bin/env perl
# $Id$
#
# mavis_tacplus_ldap.pl
# (C)2001-2020 Marc Huber <Marc.Huber@web.de>
# All rights reserved.
#
# TACACS+ backend for libmavis_external.so
# Authenticates/authorizes against LDAP, optionally supports password changes.
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

LDAP_SERVER_TYPE
	One of: generic tacacs_schema microsoft
	Default: tacacs_schema

LDAP_HOST
	Space-separated list of LDAP URLs or IP addresses or hostnames
	Examples: "ldap01 ldap02", "ldaps://ads01:636 ldaps://ads02:636"

LDAP_SCOPE
	LDAP search scope (base, one, sub)
	Default: sub

LDAP_BASE
	Base DN of your LDAP server
	Example: "dc=example,dc=com"

LDAP_CONNECT_TIMEOUT
	Timeout for initital connect to remote LDAP server. Default: 5

LDAP_FILTER
	LDAP search filter
	Defaults depend on LDAP_SERVER_TYPE:
	- generic:			"(uid=%s)"
	- tacacs_schema:	"(&(uid=%s)(objectClass=tacacsAccount))"
	- microsoft:		"(&(objectclass=user)(sAMAccountName=%s))"

LDAP_FILTER_CHPW
	LDAP search filter for password changes
	Defaults depend on LDAP_SERVER_TYPE:
	- generic:			"(uid=%s)"
	- tacacs_schema:	"(&(uid=%s)(objectClass=tacacsAccount)(!(tacacsFlag=staticpasswd))"
	- microsoft:		"(&(objectclass=user)(sAMAccountName=%s))"

LDAP_USER
	User to use for LDAP bind if server doesn't permit anonymous searches.
	Default: unset

LDAP_PASSWD
	Password for LDAP_USER
	Default: unset

AD_GROUP_PREFIX
	An AD group starting with this prefix will be used for tacacs group membership.
	Default: tacacs

REQUIRE_AD_GROUP_PREFIX
	If set, user needs to be in one of the AD_GROUP_PREFIX groups.
	Default: unset

UNLIMIT_AD_GROUP_MEMBERSHIP
	If unset, the number of groups a user can be member of is limited to one.
	Default: unset

EXPAND_AD_GROUP_MEMBERSHIP
	If set, AD group memberships will be expanded.
	Default: unset

USE_TLS
	If set, the server is required to support start_tls. Do not use this for plain LDAPS.
	Default: unset

FLAG_CHPW
	Permit password changes via this backend.
	Default: unset

FLAG_PWPOLICY
	Enforce a simplicistic password policy.
	Default: unset

FLAG_CACHE_CONNECTION
	Keep connection to LDAP server open.
	Default: unset

FLAG_FALLTHROUGH
	If LDAP search fails, try next module (if any).
	Default: unset

FLAG_USE_MEMBEROF
	Use the memberof attribute for determining group membership.
	Default: unset

FLAG_AUTHORIZE_ONLY
	Don't attempt to authenticate users.

TLS_OPTIONS
	Extra options for use with LDAPS or start_tls, in Perl hash syntax.
	See https://metacpan.org/pod/Net::LDAP for details.
	Default: unset
	Example: "sslversion => 'tlsv1_2'"

########

Sample configuration:

	id = spawnd {
		listen = {
			port = 49
		}
		spawn = {
			instances min = 1
			instances max = 10
		}
		background = no
	}

	id = tac_plus {
		access log = /var/log/tacacs/%Y/%m/%d/access.log
		accounting log = /var/log/tacacs/%Y/%m/%d/acct.log

		mavis module = external {
			# # Optionally:
			# script out = {
			# 	if (undef($TACMEMBER) && $RESULT == ACK) set RESULT = NAK
			# }

			setenv LDAP_SERVER_TYPE = "microsoft"
			setenv LDAP_HOSTS = "ldaps://ads01:636 ldaps://ads02:636"
			setenv LDAP_BASE = "dc=example,dc=com"
			setenv LDAP_USER = tacacs@example.com
			setenv LDAP_PASSWD = Secret123
			setenv REQUIRE_AD_GROUP_PREFIX = 1
			setenv FLAG_CHPW = 1
			exec = /usr/local/lib/mavis/mavis_tacplus_ldap.pl
		}

		user backend = mavis	# query backend for users
		login backend = mavis	# authenticate login via backend
		pap backend = mavis		# authenticate PAP via backend

		host = world {
			address = ::/0
			prompt = "Welcome\n"
			key = cisco
		}

		host = helpdesklab {
				address = 192.168.34.16/28
		}

# A user will be in the "admin" group if he's member of the
# corresponding "tacacsadmin" ADS group. See $tacacsGroupPrefix
# and $require_tacacsGroupPrefix in the code.

		group = admin {
			default service = permit
			service = shell {
				default command = permit
				default attribute = permit
				set priv-lvl = 15
			}
		}

# A user will be in the "helpdesk" group if he's member of the
# corresponding "tacacshelpdesk" ADS group:

		group = helpdesk {
			default service = permit
			service = shell {
				default command = permit
				default attribute = permit
				set priv-lvl = 1
			}
			enable = deny
			member = admin@helpdesklab
		}
	}

=cut

use lib '/usr/local/lib/mavis/';

use strict;
use Mavis;

my $LDAP_SERVER_TYPE	= 'tacacs_schema';
my $LDAP_MASTER			= ['ldap01'];
my $LDAP_HOSTS			= ['ldap03', 'ldap04', 'ldap01', 'ldap02'];
my @LDAP_BIND			= ();
my $LDAP_BASE			= 'ou=staff,dc=example,dc=com';
my $LDAP_CONNECT_TIMEOUT = 5;
my $LDAP_SCOPE			= 'sub';
my $LDAP_FILTER			= '(uid=%s)';
my $LDAP_FILTER_CHPW	= '(uid=%s)';
my $use_tls				= undef;
my $flag_chpass			= undef;
my $flag_pwpolicy		= undef;
my $flag_cacheconn		= undef;
my $flag_fallthrough	= undef;
my $flag_use_memberof	= undef;
my $flag_authorize_only	= undef;
my %tls_options;

my $tacacsGroupPrefix	= 'tacacs';
my $require_tacacsGroupPrefix = undef;
my $unlimit_ad_group_membership = undef;
my $expand_ad_group_membership = undef;

$LDAP_SERVER_TYPE		= $ENV{'LDAP_SERVER_TYPE'} if exists $ENV{'LDAP_SERVER_TYPE'};
$flag_chpass			= $ENV{'FLAG_CHPW'} if exists $ENV{'FLAG_CHPW'};
$flag_pwpolicy			= $ENV{'FLAG_PWPOLICY'} if exists $ENV{'FLAG_PWPOLICY'};
$flag_cacheconn			= $ENV{'FLAG_CACHE_CONNECTION'} if exists $ENV{'FLAG_CACHE_CONNECTION'};
$flag_fallthrough		= $ENV{'FLAG_FALLTHROUGH'} if exists $ENV{'FLAG_FALLTHROUGH'};
$flag_use_memberof		= $ENV{'FLAG_USE_MEMBEROF'} if exists $ENV{'FLAG_USE_MEMBEROF'};
$flag_authorize_only	= $ENV{'FLAG_AUTHORIZE_ONLY'} if exists $ENV{'FLAG_AUTHORIZE_ONLY'};

print STDERR "Default server type is \'$LDAP_SERVER_TYPE\'. You probably need to change that to 'generic' or 'microsoft'.\n" unless exists $ENV{'LDAP_SERVER_TYPE'};

if ($LDAP_SERVER_TYPE eq 'tacacs_schema') {
	$LDAP_FILTER	= '(&(uid=%s)(objectClass=tacacsAccount))';
	$LDAP_FILTER_CHPW = '(&(uid=%s)(objectClass=tacacsAccount)(!(tacacsFlag=staticpasswd)))';
} elsif ($LDAP_SERVER_TYPE eq 'microsoft') {
	$LDAP_FILTER	= '(&(objectclass=user)(sAMAccountName=%s))';
	$LDAP_FILTER_CHPW = $LDAP_FILTER;
	$flag_use_memberof = 1;
} else {
	$LDAP_FILTER	= '(uid=%s)';
	$LDAP_FILTER_CHPW = $LDAP_FILTER;
}

%tls_options = eval $ENV{'TLS_OPTIONS'} if exists $ENV{'TLS_OPTIONS'};

if (exists $ENV{'LDAP_HOSTS'}) {
	$LDAP_HOSTS	= [];
	for my $h (split /\s+/, $ENV{'LDAP_HOSTS'}) {
		push @$LDAP_HOSTS, $h;
	}
	$LDAP_MASTER = @$LDAP_HOSTS[0];
}

$LDAP_SCOPE			= $ENV{'LDAP_SCOPE'} if exists $ENV{'LDAP_SCOPE'};
$LDAP_BASE			= $ENV{'LDAP_BASE'} if exists $ENV{'LDAP_BASE'};
$LDAP_FILTER		= $ENV{'LDAP_FILTER'} if exists $ENV{'LDAP_FILTER'};
$LDAP_FILTER_CHPW	= $ENV{'LDAP_FILTER_CHPW'} if exists $ENV{'LDAP_FILTER_CHPW'};
$LDAP_CONNECT_TIMEOUT	= $ENV{'LDAP_CONNECT_TIMEOUT'} if exists $ENV{'LDAP_CONNECT_TIMEOUT'};
@LDAP_BIND			= ($ENV{'LDAP_USER'}, password => $ENV{'LDAP_PASSWD'}) if (exists $ENV{'LDAP_USER'} && exists $ENV{'LDAP_PASSWD'});
$flag_use_memberof		= $ENV{'USE_MEMBEROF'} if exists $ENV{'USE_MEMBEROF'};
$use_tls			= $ENV{'USE_TLS'} if exists $ENV{'USE_TLS'};
$tacacsGroupPrefix	= $ENV{'TACACS_GROUP_PREFIX'} if exists $ENV{'TACACS_GROUP_PREFIX'};
$tacacsGroupPrefix	= $ENV{'TACACS_AD_GROUP_PREFIX'} if exists $ENV{'TACACS_AD_GROUP_PREFIX'};
$tacacsGroupPrefix	= $ENV{'AD_GROUP_PREFIX'} if exists $ENV{'AD_GROUP_PREFIX'};
$require_tacacsGroupPrefix = $ENV{'REQUIRE_TACACS_GROUP_PREFIX'} if exists $ENV{'REQUIRE_TACACS_GROUP_PREFIX'};
$require_tacacsGroupPrefix = $ENV{'REQUIRE_TACACS_AD_GROUP_PREFIX'} if exists $ENV{'REQUIRE_TACACS_AD_GROUP_PREFIX'};
$require_tacacsGroupPrefix = $ENV{'REQUIRE_AD_GROUP_PREFIX'} if exists $ENV{'REQUIRE_AD_GROUP_PREFIX'};
$unlimit_ad_group_membership = $ENV{'UNLIMIT_AD_GROUP_MEMBERSHIP'} if exists $ENV{'UNLIMIT_AD_GROUP_MEMBERSHIP'};
$expand_ad_group_membership = $ENV{'EXPAND_AD_GROUP_MEMBERSHIP'} if exists $ENV{'EXPAND_AD_GROUP_MEMBERSHIP'};

unless (defined $flag_use_memberof) {
	foreach my $v ('TACACS_GROUP_PREFIX', 'REQUIRE_TACACS_GROUP_PREFIX', 'UNLIMIT_AD_GROUP_MEMBERSHIP',
				   'EXPAND_AD_GROUP_MEMBERSHIP', 'TACACS_AD_GROUP_PREFIX', 'REQUIRE_TACACS_AD_GROUP_PREFIX',
				   'AD_GROUP_PREFIX', 'REQUIRE_AD_GROUP_PREFIX') {
		printf STDERR "Warning: Environment variable $v will be ignored.\n" if exists $ENV{$v};
	}
}

die "LDAP_HOSTS not defined" unless exists $ENV{'LDAP_HOSTS'};

use Net::LDAP qw(LDAP_INVALID_CREDENTIALS LDAP_CONSTRAINT_VIOLATION);
use Net::LDAP::Constant qw(LDAP_EXTENSION_PASSWORD_MODIFY);
use Net::LDAP::Extension::SetPassword;

if (defined($flag_chpass) && $LDAP_SERVER_TYPE eq 'microsoft') {
	if (eval("require Encode")) {
		import Encode;
	} else {
		$flag_chpass = undef;
		print STDERR "Warning: Encode.pm not found, disabling AD password change functionality.\n";
	}
}

if ((defined($use_tls) || ($ENV{'LDAP_HOSTS'} =~ /ldaps:/))
    && !eval("require IO::Socket::SSL")){
		print STDERR "Warning: IO::Socket::SSL.pm not found. Neither StartTLS nor LDAPS connections will work.\n";
}

if (!defined($use_tls) && defined($flag_chpass) && $ENV{'LDAP_HOSTS'} !~ /ldaps:/ && $LDAP_SERVER_TYPE eq 'microsoft') {
	print STDERR "Warning: AD password changes require LDAPS.\n";
}

$| = 1;

my ($in);
my $has_extension_password_modify = undef;

$/ = "\n=\n";

my $ldap = undef;

my @V;

sub get_memberof($) {
	my $mesg = $ldap->search(base => $_[0], scope=>'base', filter=>'(objectclass=*)', attrs=>['memberOf']);
	if ($mesg->code){
		$V[AV_A_USER_RESPONSE] = $mesg->error . " (" . __LINE__ . ")";
		goto fatal;
	}
	my $entry = $mesg->entry(0);
	return $entry->get_value('memberof', asref => 1) if $entry;
	return [ ];
}

sub expand_memberof_sub($$);

sub expand_memberof_sub($$) {
	my ($a, $H) = @_;
	foreach my $m(@$a) {
		unless (exists $H->{$m}) {
			$H->{$m} = 1;
			my $g = get_memberof($m);
			expand_memberof_sub($g, $H);
		}
	}
}

sub expand_memberof($) {
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
		$ldap = Net::LDAP->new($LDAP_HOSTS, timeout=>$LDAP_CONNECT_TIMEOUT, %tls_options);
		unless ($ldap) {
			$V[AV_A_USER_RESPONSE] = "No answer from LDAP backend.";
			goto fatal;
		}
		if (defined $use_tls) {
			my $mesg = $ldap->start_tls(%tls_options);
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
		$V[AV_A_USER_RESPONSE] = $mesg->error . " (" . __LINE__ . ")";
		goto fatal;
	}

	$mesg = $ldap->search(base => $LDAP_BASE,
						  filter => sprintf ($V[AV_A_TACTYPE] eq AV_V_TACTYPE_CHPW ? $LDAP_FILTER_CHPW
																				   : $LDAP_FILTER,
											 $V[AV_A_USER]),
						  scope => $LDAP_SCOPE, attrs => ['1.1']);
	if ($mesg->code){
		goto down if defined($flag_fallthrough);
		$V[AV_A_USER_RESPONSE] = $mesg->error . " (" . __LINE__ . ")";
		goto fatal;
	}
	foreach my $entry ($mesg->entries){
		$authdn = $entry->dn if (!defined $authdn) || (length $entry->dn < length $authdn);
	}
	if ($authdn){
		if (defined($flag_authorize_only)){
			# skip authentication code
		} elsif ($V[AV_A_TACTYPE] eq AV_V_TACTYPE_AUTH){
			$mesg =  $ldap->bind($authdn, password => $V[AV_A_PASSWORD]);
			if ($mesg->code) {
				$V[AV_A_USER_RESPONSE] = $mesg->error . " (" . __LINE__ . ")";
				goto fail if ($mesg->code == LDAP_INVALID_CREDENTIALS || $mesg->code == LDAP_CONSTRAINT_VIOLATION);
				goto fatal;
			}
		} elsif (defined ($flag_chpass) && ($V[AV_A_TACTYPE] eq AV_V_TACTYPE_CHPW)){
			if (defined($flag_pwpolicy)) {
				# Reject passwords that are obviously too weak:
				if ($V[AV_A_PASSWORD_NEW] =~ /^.?.?.?.?.?.?.?$/ || $V[AV_A_PASSWORD_NEW] !~ /\d/
				|| $V[AV_A_PASSWORD_NEW] !~ /[a-z]+/ || $V[AV_A_PASSWORD_NEW] !~ /[A-Z]+/){
					$V[AV_A_USER_RESPONSE] =
						"Password must consist of at least 8 characters, ".
						"include an uppercase letter, a lowercase letter ".
						"and a digit.";
					goto fail;
				}
			}

			if ($LDAP_SERVER_TYPE eq 'microsoft') {
				# AD Password change code based on
				#  http://www.letu.edu/people/markroedel/netcccu/activedirectorypasswordchanges.htm
				#  http://search.cpan.org/~gbarr/perl-ldap/lib/Net/LDAP/FAQ.pod#..._in_MS_Active_Directory_?

				my $opass = Encode::encode("UTF-16LE", '"' . $V[AV_A_PASSWORD] . '"');
				my $npass = Encode::encode("UTF-16LE", '"' . $V[AV_A_PASSWORD_NEW] . '"');

				$mesg =  $ldap->bind($authdn, password => $V[AV_A_PASSWORD]);

				# from robert.dahlem@gmail.com:
				if ($#LDAP_BIND > -1 && $mesg->code == LDAP_INVALID_CREDENTIALS) {
					# typical answer from Windows Server 2008 R2:
					#	"80090308: LdapErr: DSID-0C0903A9, comment: AcceptSecurityContext error, data 773, v1db1"
					# error values from http://support.microsoft.com/kb/155012
					my $ERROR_PASSWORD_EXPIRED="532";
					my $ERROR_PASSWORD_MUST_CHANGE="773";
					my $m=$mesg->error . " (" . __LINE__ . ")";
					$m =~ s/.*DSID-0C0903A9.*, data ([0-9A-Fa-f]+),.*/$1/;
					if($m eq $ERROR_PASSWORD_MUST_CHANGE || $m eq $ERROR_PASSWORD_EXPIRED) {
						$m = $ldap->bind(@LDAP_BIND);
						$mesg = $m unless $m->code;
					}
				}

				if ($mesg->code) {
					$V[AV_A_USER_RESPONSE] = $mesg->error . " (" . __LINE__ . ")";
					goto fail if ($mesg->code == LDAP_INVALID_CREDENTIALS || $mesg->code == LDAP_CONSTRAINT_VIOLATION);
					goto fatal;
				}

				$mesg = $ldap->modify($authdn, changes => [ delete => [ unicodePwd => $opass ], add => [ unicodePwd => $npass ] ]);

			} else {
				if (defined $ldap) {
					$ldap->unbind;
					$ldap->disconnect;
					$ldap = undef;
				}
				$ldap = Net::LDAP->new($LDAP_MASTER, %tls_options);
				unless ($ldap) {
					$V[AV_A_USER_RESPONSE] = "No answer from LDAP backend.";
					goto fatal;
				}
				if (defined $use_tls) {
					$mesg = $ldap->start_tls(%tls_options);
					if ($mesg->code) {
						$V[AV_A_USER_RESPONSE] = "TLS negotiation failed.";
						goto fatal;
					}
				}
				$mesg =  $ldap->bind($authdn, password => $V[AV_A_PASSWORD]);
				if ($mesg->code) {
					$V[AV_A_USER_RESPONSE] = $mesg->error . " (" . __LINE__ . ")";
					goto fail if ($mesg->code == LDAP_INVALID_CREDENTIALS || $mesg->code == LDAP_CONSTRAINT_VIOLATION);
					goto fatal;
				}

				unless (defined $has_extension_password_modify) {
					$has_extension_password_modify =
						$ldap->root_dse->supported_extension(LDAP_EXTENSION_PASSWORD_MODIFY);
				}

				if (0 == $has_extension_password_modify) {
					my $cr = "{crypt}" . crypt($V[AV_A_PASSWORD_NEW], join '', ('.', '/', 0..9, 'A'..'Z', 'a'..'z')[rand 64, rand 64]);
					$mesg = $ldap->modify($authdn, replace => { 'userPassword' => $cr });
				} else {
					$mesg = $ldap->set_password(oldpasswd => $V[AV_A_PASSWORD], newpasswd => $V[AV_A_PASSWORD_NEW]);
				}
			}

			if ($mesg->code){
				if ($mesg->error =~ /CONSTRAINT_ATT_TYPE/s) {
					$V[AV_A_USER_RESPONSE] = "Password change rejected by policy.";
				} else {
					$V[AV_A_USER_RESPONSE] = $mesg->error;
				}
				print STDERR "chpw for ", $authdn, ": ", $mesg->error, " (" , __LINE__ , ")", "\n";
				goto fatal;
			}
			$V[AV_A_USER_RESPONSE] = "Password change was successful.";
		}

		$V[AV_A_DN] = $authdn;

		$mesg = $ldap->search(base => $authdn, scope=>'base', filter=>'(objectclass=*)', attrs=>['shadowExpire','tacacsClient','tacacsMember','tacacsProfile','memberOf']);
		if ($mesg->code){
			$V[AV_A_USER_RESPONSE] = $mesg->error . " (" . __LINE__ . ")";
			goto fatal;
		}

		my $entry = $mesg->entry(0);

		if ($LDAP_SERVER_TYPE eq 'tacacs_schema') {
			my $val;
			if (undef($flag_authorize_only)) {
					$val = $entry->get_value('shadowExpire');
					if ($val && $val > -1 && $val * 86400 < time){
						$V[AV_A_USER_RESPONSE] = "Password has expired.";
						goto fail;
				}
			}

			$val = $entry->get_value('tacacsClient', asref => 1);
			$V[AV_A_TACCLIENT] = join(',', @$val) if $val;

			$val = $entry->get_value('tacacsMember', asref => 1);
			$V[AV_A_TACMEMBER] = join(',', @$val) if $val;

			$val = $entry->get_value('tacacsProfile', asref => 1);
			$V[AV_A_TACPROFILE] = join('_X#x_', @$val) if $val;
			if (defined $V[AV_A_TACPROFILE]) {
				$V[AV_A_TACPROFILE] =~ s/}\s*_X#x_\s*{/ /sg;
			}
		} elsif (defined $flag_use_memberof) {
			my $val = $entry->get_value('memberof', asref => 1);
			if ($#{$val} > -1) {
				$val = expand_memberof($val)
					if defined $expand_ad_group_membership;
				my $m;
				foreach $m (sort grep { /^CN=$tacacsGroupPrefix[^,]*,/i } @$val) {
					my $m2 = "$m";
					$m2 =~ s/^CN=$tacacsGroupPrefix([^,]*),.*$/$1/i;
					if ($m2) {
						if (exists $V[AV_A_TACMEMBER]) {
							$V[AV_A_TACMEMBER] .= ',"' . $m2 . '"';
						} else {
							$V[AV_A_TACMEMBER] = '"' . $m2 . '"';
						}
						last unless defined($unlimit_ad_group_membership);
					}
				}
				foreach $m (sort grep { /^CN=$tacacsGroupPrefix[^,]*,/i } @$val) {
					if (exists $V[AV_A_MEMBEROF]) {
						$V[AV_A_MEMBEROF] .= ',"' . $m . '"';
					} else {
						$V[AV_A_MEMBEROF] = '"' . $m . '"';
					}
				}
			}
			if (defined ($require_tacacsGroupPrefix) && !defined($V[AV_A_TACMEMBER])){
				goto fail;
			}
		}

		if (defined($flag_authorize_only) && $V[AV_A_TACTYPE] ne AV_V_TACTYPE_INFO){
			# Attributes are set, continue with next module for authentication.
			goto down;
		} else {
			my $val = $entry->get_value('shadowExpire');
			if ($val && $val * 86400 < time){
				$V[AV_A_USER_RESPONSE] = "Password has expired.";
				goto fail;
			}
			$V[AV_A_RESULT] = AV_V_RESULT_OK;
		}
	} else {
		goto down;
	}
	$result = MAVIS_FINAL;
	goto bye;

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
