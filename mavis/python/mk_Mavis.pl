#!/usr/bin/env perl
# A trivial script for generating Mavis.pm from ../mavis.h
#
# I currently only care about the #define's ... -MH
#

open H, "../mavis.h" or die;
while (<H>) {
	next if /^#define\s+AV_A_SPARE/;
	if (/^#define\s+((MAVIS_|AV_A|AV_V)[^\s]+)\s+([^\s]+)/) {
		$V{$1} = $3;
	}
}
close H;

print<<EOT;
# Mavis module
#
# MAVIS definitions for Python, automatically generated from mavis.h
#

EOT

foreach $v (sort keys %V) {
	$V{$v} = $V{$V{$v}} unless $V{$v} =~ /^("|-|\d)/;
	print "$v = $V{$v}\n";
}

print <<EOT;

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
			line = line.rstrip('\\n')
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
				val = self.av_pairs[key].replace('\\n', '\\r')
				print(str(key) + " " + val)
		print("=" + str(verdict))
		sys.stdout.flush()

	def valid(self):
		if not AV_A_USER in self.av_pairs:
			self.write(MAVIS_FINAL, AV_V_RESULT_ERROR, "User not set.")
			return False

		if re.match('\\(|\\)|,|\\||&|=|\\*', self.av_pairs[AV_A_USER]):
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
				line = line.rstrip('\\n')
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
EOT

