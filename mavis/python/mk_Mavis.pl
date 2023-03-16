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

