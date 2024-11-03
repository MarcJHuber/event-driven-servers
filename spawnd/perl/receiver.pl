#!/usr/bin/env perl
# receiver.pl
# sample spawnd client
# (C) 2001 Marc Huber <Marc.Huber@web.de>
# All rights reserved.
#

use lib ".";

use ExtUtils::testlib;
use IO::Poll qw(POLLIN POLLHUP POLLERR);
use POSIX qw(dup close dup2 open O_RDWR);
use Scm;

use strict;

sub init;		# initialization tasks, e.g. establishing database connection
sub main;		# main task
sub finish;		# termination

-t STDIN && die
	"Don't run this program by hand. It expects ancillary messages on\n" .
	"standard input and needs to be run by spawnd.\n";

my ($poll) = new IO::Poll;
my ($pollfd) = new IO::Handle;

my ($devnull) = open ("/dev/null", O_RDWR);
while ($devnull < 2)
{
	die if $devnull < 0;
	$devnull = dup ($devnull);
}
dup2 ($devnull, 1);
my ($scm_socket) = dup (0);
dup2 ($devnull, 0);

$pollfd->fdopen($scm_socket, "r+");
autoflush $pollfd 1;
finish if Scm::scm_sendmsg($scm_socket, Scm::SCM_MAX, 1, -1);

for (;;)
{
	$poll->mask($pollfd=>POLLIN|POLLHUP|POLLERR);
	$poll->poll(120000);
	my ($ev) = $poll->events($pollfd);
	if($ev & POLLIN)
	{
		my ($msg);
		my ($fd) = -1;
		finish if Scm::scm_recvmsg($scm_socket, $msg, $fd);
		if ($msg eq "ACCEPT" && $fd > -1)
		{
			dup2 ($fd, 0) unless $fd == 0;
			dup2 ($fd, 1) unless $fd == 1;
			close ($fd) unless $fd < 2;
			autoflush STDOUT 1;
			main;
			dup2 ($devnull, 0);
			dup2 ($devnull, 1);
			finish if Scm::scm_sendmsg($scm_socket, Scm::SCM_DONE, 1, -1);
		}
		elsif ($msg eq "MAY-DIE")
		{
			finish;
		}
	}
	elsif ($ev || Scm::scm_sendmsg($scm_socket, Scm::SCM_KEEPALIVE, -1, -1))
	{
		finish;
	}
}

# End of glue code.

sub init
{
}

sub finish
{
	exit (0);
}

sub main
{
	print "Hello again. PID is $$\r\n";
	sleep 10;
}
# vim: ts=4
