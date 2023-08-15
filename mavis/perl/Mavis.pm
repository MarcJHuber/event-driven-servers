# Mavis.pm
#
# MAVIS definitions for Perl, automatically generated from mavis.h
#
package Mavis;
use strict;
use warnings;

BEGIN {
	use Exporter ();
	our (@ISA, @EXPORT);
	@ISA = qw(Exporter);
	@EXPORT = qw(
		AV_A_ANON_INCOMING
		AV_A_ARGS
		AV_A_ARRAYSIZE
		AV_A_CERTSUBJ
		AV_A_CHALLENGE
		AV_A_CLASS
		AV_A_COMMENT
		AV_A_CURRENT_MODULE
		AV_A_CUSTOM_0
		AV_A_CUSTOM_1
		AV_A_CUSTOM_2
		AV_A_CUSTOM_3
		AV_A_DBCERTSUBJ
		AV_A_DBPASSWORD
		AV_A_DN
		AV_A_EMAIL
		AV_A_FTP_ANONYMOUS
		AV_A_GID
		AV_A_GIDS
		AV_A_HOME
		AV_A_IDENTITY_SOURCE
		AV_A_IPADDR
		AV_A_LIMIT
		AV_A_MEMBEROF
		AV_A_PASSWORD
		AV_A_PASSWORD_MUSTCHANGE
		AV_A_PASSWORD_NEW
		AV_A_PASSWORD_ONESHOT
		AV_A_PATH
		AV_A_QUOTA_LIMIT
		AV_A_QUOTA_PATH
		AV_A_RARGS
		AV_A_REALM
		AV_A_RESULT
		AV_A_ROOT
		AV_A_SERIAL
		AV_A_SERVERIP
		AV_A_SHELL
		AV_A_SSHKEY
		AV_A_SSHKEYHASH
		AV_A_SSHKEYID
		AV_A_TACCLIENT
		AV_A_TACMEMBER
		AV_A_TACPROFILE
		AV_A_TACTYPE
		AV_A_TIMESTAMP
		AV_A_TRAFFICSHAPING
		AV_A_TYPE
		AV_A_UID
		AV_A_UMASK
		AV_A_USER
		AV_A_USER_RESPONSE
		AV_A_VERDICT
		AV_A_VHOST
		AV_V_BOOL_FALSE
		AV_V_BOOL_TRUE
		AV_V_RESULT_ERROR
		AV_V_RESULT_FAIL
		AV_V_RESULT_NOTFOUND
		AV_V_RESULT_OK
		AV_V_TACTYPE_AUTH
		AV_V_TACTYPE_CHAL
		AV_V_TACTYPE_CHPW
		AV_V_TACTYPE_INFO
		AV_V_TYPE_FTP
		AV_V_TYPE_LOGSTATS
		AV_V_TYPE_PRIVATE_PREFIX
		AV_V_TYPE_PRIVATE_PREFIX_LEN
		AV_V_TYPE_TACPLUS
		MAVIS_API_VERSION
		MAVIS_CONF_ERR
		MAVIS_CONF_OK
		MAVIS_DEFERRED
		MAVIS_DOWN
		MAVIS_FINAL
		MAVIS_FINAL_DEFERRED
		MAVIS_IGNORE
		MAVIS_INIT_ERR
		MAVIS_INIT_OK
		MAVIS_TIMEOUT

	);
};

use constant AV_A_ANON_INCOMING => 29;
use constant AV_A_ARGS => 26;
use constant AV_A_ARRAYSIZE => 56;
use constant AV_A_CERTSUBJ => 44;
use constant AV_A_CHALLENGE => 51;
use constant AV_A_CLASS => 34;
use constant AV_A_COMMENT => 17;
use constant AV_A_CURRENT_MODULE => 55;
use constant AV_A_CUSTOM_0 => 38;
use constant AV_A_CUSTOM_1 => 39;
use constant AV_A_CUSTOM_2 => 40;
use constant AV_A_CUSTOM_3 => 41;
use constant AV_A_DBCERTSUBJ => 45;
use constant AV_A_DBPASSWORD => 36;
use constant AV_A_DN => 5;
use constant AV_A_EMAIL => 23;
use constant AV_A_FTP_ANONYMOUS => 22;
use constant AV_A_GID => 10;
use constant AV_A_GIDS => 24;
use constant AV_A_HOME => 19;
use constant AV_A_IDENTITY_SOURCE => 37;
use constant AV_A_IPADDR => 14;
use constant AV_A_LIMIT => 11;
use constant AV_A_MEMBEROF => 1;
use constant AV_A_PASSWORD => 8;
use constant AV_A_PASSWORD_MUSTCHANGE => 53;
use constant AV_A_PASSWORD_NEW => 50;
use constant AV_A_PASSWORD_ONESHOT => 52;
use constant AV_A_PATH => 7;
use constant AV_A_QUOTA_LIMIT => 15;
use constant AV_A_QUOTA_PATH => 16;
use constant AV_A_RARGS => 28;
use constant AV_A_REALM => 27;
use constant AV_A_RESULT => 6;
use constant AV_A_ROOT => 20;
use constant AV_A_SERIAL => 21;
use constant AV_A_SERVERIP => 25;
use constant AV_A_SHELL => 54;
use constant AV_A_SSHKEY => 12;
use constant AV_A_SSHKEYHASH => 2;
use constant AV_A_SSHKEYID => 18;
use constant AV_A_TACCLIENT => 46;
use constant AV_A_TACMEMBER => 47;
use constant AV_A_TACPROFILE => 48;
use constant AV_A_TACTYPE => 49;
use constant AV_A_TIMESTAMP => 3;
use constant AV_A_TRAFFICSHAPING => 13;
use constant AV_A_TYPE => 0;
use constant AV_A_UID => 9;
use constant AV_A_UMASK => 31;
use constant AV_A_USER => 4;
use constant AV_A_USER_RESPONSE => 32;
use constant AV_A_VERDICT => 33;
use constant AV_A_VHOST => 30;
use constant AV_V_BOOL_FALSE => "FALSE";
use constant AV_V_BOOL_TRUE => "TRUE";
use constant AV_V_RESULT_ERROR => "ERR";
use constant AV_V_RESULT_FAIL => "NAK";
use constant AV_V_RESULT_NOTFOUND => "NFD";
use constant AV_V_RESULT_OK => "ACK";
use constant AV_V_TACTYPE_AUTH => "AUTH";
use constant AV_V_TACTYPE_CHAL => "CHAL";
use constant AV_V_TACTYPE_CHPW => "CHPW";
use constant AV_V_TACTYPE_INFO => "INFO";
use constant AV_V_TYPE_FTP => "FTP";
use constant AV_V_TYPE_LOGSTATS => "PRIV_LOGSTATS";
use constant AV_V_TYPE_PRIVATE_PREFIX => "PRIV_";
use constant AV_V_TYPE_PRIVATE_PREFIX_LEN => 5;
use constant AV_V_TYPE_TACPLUS => "TACPLUS";
use constant MAVIS_API_VERSION => "5";
use constant MAVIS_CONF_ERR => 1;
use constant MAVIS_CONF_OK => 0;
use constant MAVIS_DEFERRED => 1;
use constant MAVIS_DOWN => 16;
use constant MAVIS_FINAL => 0;
use constant MAVIS_FINAL_DEFERRED => 4;
use constant MAVIS_IGNORE => 2;
use constant MAVIS_INIT_ERR => 1;
use constant MAVIS_INIT_OK => 0;
use constant MAVIS_TIMEOUT => 3;


END { }

1;
