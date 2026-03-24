#!/usr/bin/env perl
# type6.pl
#
# type6 encryption/decryption for tac_plus-ng and IOS configurations

# Encrypt single key:
#  type6.pl -e MASTER_KEY TEXT
# Dencrypt single key:
#  type6.pl -d MASTER_KEY TEXT
#
#
# Encrypt stream from stdin to stdout:
#  type6.pl -e MASTER_KEY
# Dencrypt stream from stdin to stdout:
#  type6.pl -d MASTER_KEY

use strict;
use warnings;
use Digest::MD5 qw(md5);
use Digest::HMAC_SHA1 qw(hmac_sha1);
use Crypt::Cipher::AES;

my $TYPE6_SALT_LEN = 8;
my $TYPE6_MAC_LEN  = 4;
my $B41_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghi";

my %B41_IDX = map { substr($B41_CHARS, $_, 1) => $_ } 0..(length($B41_CHARS)-1);

sub base41_decode_triplet {
	my ($a, $b, $c) = @_;
	return undef unless exists $B41_IDX{$a} && exists $B41_IDX{$b} && exists $B41_IDX{$c};
	my $num = $B41_IDX{$a} * 41 * 41 + $B41_IDX{$b} * 41 + $B41_IDX{$c};
	return pack("n", $num);
}

sub b41_decode {
	my ($str) = @_;
	return undef if length($str) % 3;
	my $out = "";
	for (my $i = 0; $i < length($str); $i += 3) {
		$out .= base41_decode_triplet(substr($str,$i,1),substr($str,$i+1,1),substr($str,$i+2,1));
	}
	# drop pad
	$out =~ s/\x00\x01$// or $out =~ s/\x00$//;
	return $out;
}

sub base41_encode_pair {
	my ($bytes) = @_;
	my $val = unpack("n", $bytes);
	my $z = $val % 41; $val = int($val / 41);
	my $y = $val % 41; $val = int($val / 41);
	my $x = $val;
	return substr($B41_CHARS, $x, 1) . substr($B41_CHARS, $y, 1) . substr($B41_CHARS, $z, 1);
}

sub b41_encode {
	my ($data) = @_;
	my $out = "";
	my $len = length($data);
	for (my $i = 0; $i < $len; $i += 2) {
		my $pair = substr($data, $i, 2);
		if (length($pair) == 1) { $pair .= "\x00" }
		$out .= base41_encode_pair($pair);
	}
	# append pad based on parity
	$out .= base41_encode_pair("\x00\x01") unless $len & 1;
	return $out;
}

sub aes_stream_xor {
	my ($master_key, $salt, $ciphertext) = @_;

	my $md5digest = md5($master_key);
	my $aes_for_key = Crypt::Cipher::AES->new($md5digest);

	my $ctrkey_block = $salt . ("\x00" x 7) . "\x01";
	my $key = $aes_for_key->encrypt($ctrkey_block);
	my $aes_ctr  = Crypt::Cipher::AES->new($key);

	my $result = "";
	my $len = length($ciphertext);
	for my $i (0..$len-1) {
		my $blocknum = int($i / 16);
		my $ctr = pack("N", $blocknum) . ("\x00" x 12);
		my $stream = $aes_ctr->encrypt($ctr);
		$result .= chr(ord(substr($ciphertext,$i,1)) ^ ord(substr($stream,$i % 16,1)));
	}
	return $result;
}

sub type6_mac {
	my ($encrypted_bytes, $master_key, $salt) = @_;
	my $md5digest = md5($master_key);
	my $aes_ka = Crypt::Cipher::AES->new($md5digest);
	my $ka = $aes_ka->encrypt($salt . ("\x00" x 8));
	my $hmac = hmac_sha1($encrypted_bytes, $ka);
	return substr($hmac,0,$TYPE6_MAC_LEN);
}

sub encrypt_type6 {
	my ($plaintext, $master_key) = @_;
	my $salt = "";
	$salt .= chr(int(rand(256))) for 1..$TYPE6_SALT_LEN;
	my $enc = aes_stream_xor($master_key, $salt, $plaintext);
	my $mac = type6_mac($enc, $master_key, $salt);
	my $blob = $salt . $enc . $mac;
	return b41_encode($blob);
}

sub decrypt_type6 {
	my ($encoded, $master_key) = @_;
	my $raw = b41_decode($encoded);
	return undef unless defined $raw;
	my $salt = substr($raw,0,$TYPE6_SALT_LEN);
	my $enc  = substr($raw,$TYPE6_SALT_LEN,-$TYPE6_MAC_LEN);
	my $mac  = substr($raw,-$TYPE6_MAC_LEN);
	my $calc_mac = type6_mac($enc, $master_key, $salt);
	return undef if $mac ne $calc_mac;
	return aes_stream_xor($master_key, $salt, $enc);
}

sub d7 {
	my ($start, $key) = $_[0] =~ /^\d\s+(..)((..)+)$/ or return $_[0];
	my $key_len = length($key);
	my $x = "dsfd;kfoA,.iyewrkldJKDHSUBsgvca69834ncxv9873254k;fg87";
	my $x_len = length($x);
	my $res = "";
	for (my $i = 0; $i < $key_len; $i += 2) {
		$res .= chr(hex(substr($key, $i, 2)) ^ ord(substr($x, $start++, 1)));
		$start %= $x_len;
	}
	return $res;
}

sub e6 {
	my ($pre, $key, $master) = @_;
	$key = d7($1) if $key =~ /^(7\s+.*)$/;
	return $pre . $key if $key =~ /^7\s/;
	$key = $1 if $key =~ /^clear\s+(.*)$/;
	$key = $1 if $key =~ /^0\s+(.*)$/;
	$key =~ s/^"(.*)"$/$1/;
	my $e = encrypt_type6($key, $master);
	return $pre . $key unless $e;
	return "${pre}6 \"$e\"" if $pre =~ /=/;
	return "${pre}6 $e";
}

sub d6 {
	my ($pre, $key, $master) = @_;
	return $pre . $key unless $key =~ /^6\s+(\S+)\s*$/;
	my $key6 = $1;
	if ($pre =~ /=/) {
		$key6 =~ s/^"(.*)"$/$1/;
		my $d = decrypt_type6($key6, $master);
		return $pre . "clear \"" . $d . "\"" if defined $d;
	} else {
		my $d = decrypt_type6($key6, $master);
		return $pre . " 0 " . $d if defined $d;
	}
	return $pre . $key;
}

sub e6_stream {
	my ($in, $master) = @_;
	$in =~ s/(key\s*[^=+]*=\s*)((7|clear)\s+\S+)/e6($1,$2, $master)/gem;
	$in =~ s/(password\s*[^=+]*=\s*)((7|clear)\s+\S+)/e6($1,$2, $master)/gem;
	$in =~ s/(enable(\s+\d+\s+)?\s*[^=+]*=\s*)((7|clear)\s+\S+)/e6($1,$3, $master)/gem;
	$in =~ s/((password|key)\s)((0|7)\s+\S+)/e6($1,$3, $master)/gem; # IOS
	return $in;
}

sub d6_stream {
	my ($in, $master) = @_;
	$in =~ s/(key\s*[^=+]*=\s*)(6\s+\S+)/d6($1, $2, $master)/gem;
	$in =~ s/(password\s*[^=+]*=\s*)(6\s+\S+)/d6($1, $2, $master)/gem;
	$in =~ s/(enable\s*[^=+]*=\s*)(6\s+\S+)/d6($1, $2, $master)/gem;
	$in =~ s/((password|key)\s+)(6\s+\S+)/d6($2, $3, $master)/gem; # IOS
	return $in;
}

die "Usage: $0 (-e|-d) MASTER_KEY [TEXT]\n" if @ARGV < 2;

my ($mode, $master, $value) = @ARGV;

if ($mode eq '-e') {
	if ($value) {
		my $enc = encrypt_type6($value, $master);
		print "$enc\n";
	} else {
		local $/;
		print e6_stream(<STDIN>, $master);
	}
} elsif ($mode eq '-d') {
	if ($value) {
		my $plain = decrypt_type6($value, $master);
		print defined $plain ? "$plain\n" : "MAC verification failed\n";
	} else {
		local $/;
		print d6_stream(<STDIN>, $master);
	}
} else {
	die "Unknown mode\n";
}

