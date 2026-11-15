#!/usr/bin/perl -w

use strict;

sub run($)
{
	my $IN;
	open $IN, $_[0];
	my $indent = 0;
	my $out = "";
	my $spaces = "  ";
	while (<$IN>) {
		if (/^(set all_graphs)\s+{/) {
			$indent++;
			$out .= $_;
			next;
		}
		s/^( |\t)+//;
		if (/^\{/) {
			$out .= $spaces x $indent;
			$indent++;
			$out .= $_;
			next
		}
		if (/^\}/) {
			$indent--;
			$indent = 0 if $indent < 0;
		}
		$out .= $spaces x $indent;
		$out .= $_;
	}
	close $IN;
	my $OUT;
	open $OUT, ">$_[0]";
	print $OUT $out;
	close $OUT;
}

foreach my $file (@ARGV)
{
	run "$file";
}
