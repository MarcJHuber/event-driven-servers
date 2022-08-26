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

$e = "";
$o = "";

foreach $v (sort keys %V) {
	$e .= "\t\t$v\n";
	$V{$v} = $V{$V{$v}} unless $V{$v} =~ /^("|-|\d)/;
	$o .= "use constant $v => $V{$v};\n";
}

print<<EOT;
# Mavis.pm
#
# MAVIS definitions for Perl, automatically generated from mavis.h
#
package Mavis;
use strict;
use warnings;

BEGIN {
	use Exporter ();
	our (\@ISA, \@EXPORT);
	\@ISA = qw(Exporter);
	\@EXPORT = qw(
$e
	);
};

$o

END { }

1;
EOT

