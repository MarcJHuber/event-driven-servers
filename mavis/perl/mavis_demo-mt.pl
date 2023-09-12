#!/usr/bin/perl -w
#
# Skeleton libmavis_external-mt support code.
#
# (C)2001-2023 Marc Huber <Marc.Huber@web.de>
#

use lib '/usr/local/lib/mavis/';
use strict;
use threads;
use threads::shared;
use Mavis;

my $write_av_lock :shared = 0;

sub write_av($$)
{
	use bytes;
	my ($av_pairs, $result) = (@_);
	my $out = "";
	foreach my $k (sort { $a <=> $b } keys %$av_pairs) {
		$out .= $k . ' ' . $av_pairs->{$k} . "\n";
	}
	$out .= "\n";
	my $out_len = length($out);
	my $answer = pack('N N N A*', MAVIS_EXT_MAGIC_V1, $out_len, $result, $out);
	lock($write_av_lock);
	syswrite(STDOUT, $answer, 12 + $out_len);
}

sub run($)
{
	threads->detach();
	my ($av_pairs) = (@_);

	# FIXME. Here's the place to process the av pairs.

	write_av($av_pairs, MAVIS_FINAL);
}

while (1) {
	my $header;
	my $header_len = sysread(STDIN, $header, 12);
	if ($header_len != 12) {
		die "Short read (header)";
	}
	my ($magic, $body_len, $result) = unpack ('N N N', $header);
	if ($magic != MAVIS_EXT_MAGIC_V1) {
		die "Bad magic.";
	}
	my $in;
	my $in_len = sysread(STDIN, $in, $body_len);
	if ($in_len != $body_len) {
		die "Short read (body)";
	}

	chop $in;

	my %av_pairs :shared = map { split(/ /, $_, 2) } split(/\n/, $in);

	threads->create(\&run, \%av_pairs);
}
