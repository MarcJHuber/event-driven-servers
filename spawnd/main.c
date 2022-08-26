/*
 * main.c
 * (C)2000-2011 by Marc Huber <Marc.Huber@web.de>
 *
 * $Id$
 *
 */

#include "mavis/spawnd_headers.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

int spawnd_main(int argc, char **, char **, char *);

int main(int argc, char **argv, char **envp)
{
    spawnd_main(argc, argv, envp, NULL);
    exit(0);
}
