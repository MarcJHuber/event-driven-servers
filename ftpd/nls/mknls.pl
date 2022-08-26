#!/usr/bin/env perl

sub utf8enc
{
  $i = 0;
  $in = $_[0];
  $out = "";

  for($i = 0; $i < length($in); $i++)
    {
	$s = substr($in, $i, 1);
	if(ord($s) & 0x80)
	{
		$out .= chr(0xc0 | (ord($s) >> 6));
		$out .= chr(0x80 | (ord($s) & 0x3f));
	}
	else
	{
		$out .= $s;
	}
    }

   return $out;
}


sub p()
{
	if($MSG{"EN"})
	{
		print C "\t{\n";
		print C "\t\t", utf8enc($MSG{"EN"}), ",\n";
		if($MSG{"DE"})
		{
			print C "\t\t", utf8enc($MSG{"DE"}), ",\n";
		}
		else
		{
			print C "\t\tNULL,\n";
		}
		print C "\t},\n";
	}
	%MSG = ();
}

$count = 0;

open MESS, "messages.txt" or die;
open H, ">../messages.h" or die;
open C, ">../messages.c" or die;

print C <<EOT

/* AUTOMATICALLY GENERATED -- DO NOT EDIT */

#define NULL (void *) 0

char *lang[] =
{
	"EN",
	"DE",
	NULL
};

char *message[][2] =
{

EOT
;

print H <<EOT

/* AUTOMATICALLY GENERATED -- DO NOT EDIT */

extern char *lang[];

extern char *message[][2];

EOT
;

while(<MESS>)
{
	chomp;
	s/\s+$//g;
	next if /^#/ or /^$/;

	/^([^\s]+)\s+(.*)/;

	if($1 eq "MSG")
	{
		p() unless $count == 0;
		print H "#define IDX_$2 $count\n";
		print H "#define MSG_$2 (message[$count][ctx->lang])\n";

		$count++;
	}
	else
	{
		$MSG{$1} = $2;
	}
}

p();

print C <<EOT;
};

void message_init(void)
{
  int i, j;
  for(i = 0; i < $count; i++)
	for(j = 1; j < 2; j++)
		if(!message[i][j])
			message[i][j] = message[i][0];
}

EOT

close MESS;
close H;
close C;

