#!/usr/bin/env perl
# A trivial script for generating Mavis.pm from ../mavis.h
#
# I currently only care about the #define's ... -MH
#

open H, "../mavis.h" or die;
while (<H>) {
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

import select, sys, os

def write(av_pairs, result):
	for key in sorted(av_pairs):
		print(str(key) + " " + av_pairs[key])
	print("=" + str(result))
	sys.stdout.flush()

def read():
	av_pairs = { }
	while sys.stdin in select.select([sys.stdin], [], [], 0)[0]:
		line = sys.stdin.readline()
		if line:
			line = line.rstrip('\\n')
			if line == "=":
				return av_pairs
			av_pair = line.split(" ", 1)
			av_pairs[int(av_pair[0])] = av_pair[1]
		else:
			break
	exit(0)

EOT

