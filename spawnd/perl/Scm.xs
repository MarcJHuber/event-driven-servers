#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#include "mavis/scm.h"

MODULE = Scm         PACKAGE = Scm

PROTOTYPES: DISABLE

int
scm_sendmsg (sock, type, fd)
	int sock
	char *type
	int fd
    CODE:
	struct scm_data sd;
	memset(&sd, 0, sizeof(sd));
	sd.type = type;
	RETVAL = scm_send_msg (sock, &sd, fd);
    OUTPUT:
	RETVAL

int
scm_recvmsg (sock, type, fd)
	int sock
	SV *type
	int fd
    CODE:
    	char input[100];
	RETVAL = scm_recv_msg (sock, input, sizeof(input), &fd);
	if (!RETVAL)
    		sv_setpv(type, input);
    OUTPUT:
	type
	fd
	RETVAL


