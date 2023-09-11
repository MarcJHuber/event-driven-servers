# Mavis module
#
# MAVIS definitions for Python, automatically generated from mavis.h
#

AV_A_ANON_INCOMING = 29
AV_A_ARGS = 26
AV_A_ARRAYSIZE = 56
AV_A_CERTSUBJ = 44
AV_A_CHALLENGE = 51
AV_A_CLASS = 34
AV_A_COMMENT = 17
AV_A_CURRENT_MODULE = 55
AV_A_CUSTOM_0 = 38
AV_A_CUSTOM_1 = 39
AV_A_CUSTOM_2 = 40
AV_A_CUSTOM_3 = 41
AV_A_DBCERTSUBJ = 45
AV_A_DBPASSWORD = 36
AV_A_DN = 5
AV_A_EMAIL = 23
AV_A_FTP_ANONYMOUS = 22
AV_A_GID = 10
AV_A_GIDS = 24
AV_A_HOME = 19
AV_A_IDENTITY_SOURCE = 37
AV_A_IPADDR = 14
AV_A_LIMIT = 11
AV_A_MEMBEROF = 1
AV_A_PASSWORD = 8
AV_A_PASSWORD_EXPIRY = 35
AV_A_PASSWORD_MUSTCHANGE = 53
AV_A_PASSWORD_NEW = 50
AV_A_PASSWORD_ONESHOT = 52
AV_A_PATH = 7
AV_A_QUOTA_LIMIT = 15
AV_A_QUOTA_PATH = 16
AV_A_RARGS = 28
AV_A_REALM = 27
AV_A_RESULT = 6
AV_A_ROOT = 20
AV_A_SERIAL = 21
AV_A_SERVERIP = 25
AV_A_SHELL = 54
AV_A_SSHKEY = 12
AV_A_SSHKEYHASH = 2
AV_A_SSHKEYID = 18
AV_A_TACCLIENT = 46
AV_A_TACMEMBER = 47
AV_A_TACPROFILE = 48
AV_A_TACTYPE = 49
AV_A_TIMESTAMP = 3
AV_A_TRAFFICSHAPING = 13
AV_A_TYPE = 0
AV_A_UID = 9
AV_A_UMASK = 31
AV_A_USER = 4
AV_A_USER_RESPONSE = 32
AV_A_VERDICT = 33
AV_A_VHOST = 30
AV_V_BOOL_FALSE = "FALSE"
AV_V_BOOL_TRUE = "TRUE"
AV_V_RESULT_ERROR = "ERR"
AV_V_RESULT_FAIL = "NAK"
AV_V_RESULT_NOTFOUND = "NFD"
AV_V_RESULT_OK = "ACK"
AV_V_TACTYPE_AUTH = "AUTH"
AV_V_TACTYPE_CHAL = "CHAL"
AV_V_TACTYPE_CHPW = "CHPW"
AV_V_TACTYPE_INFO = "INFO"
AV_V_TYPE_FTP = "FTP"
AV_V_TYPE_LOGSTATS = "PRIV_LOGSTATS"
AV_V_TYPE_PRIVATE_PREFIX = "PRIV_"
AV_V_TYPE_PRIVATE_PREFIX_LEN = 5
AV_V_TYPE_TACPLUS = "TACPLUS"
MAVIS_API_VERSION = "5"
MAVIS_CONF_ERR = 1
MAVIS_CONF_OK = 0
MAVIS_DEFERRED = 1
MAVIS_DOWN = 16
MAVIS_EXT_MAGIC_V1 = 0x4d610001
MAVIS_FINAL = 0
MAVIS_FINAL_DEFERRED = 4
MAVIS_IGNORE = 2
MAVIS_INIT_ERR = 1
MAVIS_INIT_OK = 0
MAVIS_TIMEOUT = 3

import sys, os, re

def write(av_pairs, result):
	for key in sorted(av_pairs):
		if av_pairs[key] is not None:
			print(str(key) + " " + av_pairs[key])
	print("=" + str(result))
	sys.stdout.flush()

def read():
	av_pairs = { }
	for line in sys.stdin:
		if line:
			line = line.rstrip('\n')
			if line == "=":
				return av_pairs
			av_pair = line.split(" ", 1)
			av_pairs[int(av_pair[0])] = av_pair[1]
		else:
			break
	exit(0)

class Mavis:
	def write(self, verdict, result, user_response):
		self.av_pairs[AV_A_RESULT] = result
		if user_response is not None:
			self.av_pairs[AV_A_USER_RESPONSE] = user_response
		for key in sorted(self.av_pairs):
			if self.av_pairs[key]:
				val = self.av_pairs[key].replace('\n', '\r')
				print(str(key) + " " + val)
		print("=" + str(verdict))
		sys.stdout.flush()

	def valid(self):
		if not AV_A_USER in self.av_pairs:
			self.write(MAVIS_FINAL, AV_V_RESULT_ERROR, "User not set.")
			return False

		if re.match('\(|\)|,|\||&|=|\*', self.av_pairs[AV_A_USER]):
			self.write(MAVIS_FINAL, AV_V_RESULT_ERROR, "Username not valid.")
			return False

		if ((self.av_pairs[AV_A_TACTYPE] == AV_V_TACTYPE_AUTH
				or self.av_pairs[AV_A_TACTYPE] == AV_V_TACTYPE_CHPW)
			and (not AV_A_PASSWORD in self.av_pairs
				or len(self.av_pairs[AV_A_PASSWORD]) == 0)):
			self.write(MAVIS_FINAL, "Password not set.", AV_V_RESULT_ERROR)
			return False

		if ((self.av_pairs[AV_A_TACTYPE] == AV_V_TACTYPE_CHPW)
			and (not AV_A_PASSWORD_NEW in self.av_pairs
				or len(self.av_pairs[AV_A_PASSWORD_NEW]) == 0)):
			self.write(MAVIS_FINAL, AV_V_RESULT_ERROR, "New password not set.")
			return False

		return True

	def __init__(self):
		self.av_pairs = { }
		for line in sys.stdin:
			if line:
				line = line.rstrip('\n')
				if line == "=":
					self.is_tacplus_authc = (
						self.av_pairs[AV_A_TACTYPE] == AV_V_TACTYPE_AUTH
						or self.av_pairs[AV_A_TACTYPE] == AV_V_TACTYPE_CHPW)
					self.is_tacplus_authz =  self.av_pairs[AV_A_TACTYPE] == AV_V_TACTYPE_INFO
					self.is_tacplus_chpw = (
						self.av_pairs[AV_A_TACTYPE] == AV_V_TACTYPE_CHPW)
					if AV_A_USER in self.av_pairs:
						self.user = self.av_pairs[AV_A_USER]
					if AV_A_PASSWORD in self.av_pairs:
						self.password = self.av_pairs[AV_A_PASSWORD]
					if AV_A_PASSWORD_NEW in self.av_pairs:
						self.password_new = self.av_pairs[AV_A_PASSWORD_NEW]
					return None
				av_pair = line.split(" ", 1)
				self.av_pairs[int(av_pair[0])] = av_pair[1]
			else:
				break
		exit(0)

	def is_tacplus(self):
		if self.av_pairs[AV_A_TYPE] != AV_V_TYPE_TACPLUS:
			self.write(self.av_pairs, MAVIS_DOWN)
			return False
		return True

	def set_dn(self, arg):
		self.av_pairs[AV_A_DN] = arg

	def set_memberof(self, arg):
		self.av_pairs[AV_A_MEMBEROF] = arg

	def set_tacmember(self, arg):
		self.av_pairs[AV_A_TACMEMBER] = arg

	def set_dbpassword(self, arg):
		self.av_pairs[AV_A_DBPASSWORD] = arg

	def set_uid(self, arg):
		self.av_pairs[AV_A_UID] = arg

	def set_gid(self, arg):
		self.av_pairs[AV_A_GID] = arg

	def set_shell(self, arg):
		self.av_pairs[AV_A_SHELL] = arg

	def set_home(self, arg):
		self.av_pairs[AV_A_HOME] = arg

	def set_sshpubkey(self, arg):
		self.av_pairs[AV_A_SSHKEY] = arg

	def remember_password(self, arg):
		if arg:
			self.av_pairs.pop(AV_A_PASSWORD_ONESHOT, None)
		else:
			self.av_pairs[AV_A_PASSWORD_ONESHOT] = "1"

	def password_mustchange(self, arg):
		if arg:
			self.av_pairs[AV_A_PASSWORD_MUSTCHANGE] = "1"
		else:
			self.av_pairs.pop(AV_A_PASSWORD_MUSTCHANGE, None)

	def set_expiry(self, arg):
		self.av_pairs[AV_A_PASSWORD_EXPIRY] = str(arg)
