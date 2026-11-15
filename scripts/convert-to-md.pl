#!/usr/bin/perl -w
use strict;

$/ = undef;

sub remove_nl_func {
    my ($matched_text) = @_;
    
    # Remove all types of newlines (\n and \r) from the matched string
    $matched_text =~ s/[\r\n]+//g;
    
    return $matched_text;
}

my ($infile, $outfile) = @ARGV;
system ("pandoc -f docbook -t gfm --wrap=none $infile -o $outfile");
my $IN;
open($IN, $outfile) or die;
my $in = <$IN>;
close $IN;
$in =~ s/!\[([^\]]+)\]\s*\(([^\.]+)\.eps\)/

<picture>
<source media="(prefers-color-scheme: dark)" srcset="$2-dark.svg">
<img alt="$1" src="$2.svg">
<\/picture>

*$1*

/sg;

$in =~ s/(<img alt=[^>]+>)/remove_nl_func($1)/esg;
open($IN, ">$outfile");
print $IN $in;
close $IN;
exit 0
