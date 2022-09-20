#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#include "mavis/scm.h"
#include <string.h>

MODULE = Scm         PACKAGE = Scm

PROTOTYPES: DISABLE

int
scm_sendmsg (sock, type, fd)
	int sock
	int type
	int fd
    CODE:
	struct scm_data sd;
	memset(&sd, 0, sizeof(sd));
	sd.type = type;
	RETVAL = scm_send_msg (sock, &sd, fd);
    OUTPUT:
	RETVAL

int
scm_sendmsg_accept (sock, type, fd, haproxy, realm)
	int sock
	int type
	int fd
	int haproxy
	char *realm
    CODE:
	struct scm_data_accept sd;
	memset(&sd, 0, sizeof(sd));
	sd.type = type;
	sd.haproxy = haproxy ? 1 : 0;
	strncpy(sd.realm, realm, SCM_REALM_SIZE - 1);
	RETVAL = scm_send_msg (sock, (struct scm_data *) &sd, fd);
    OUTPUT:
	RETVAL

int
scm_recvmsg (sock, type, fd, realm)
	int sock
	int type
	int fd
	char *realm
    CODE:
    	struct scm_data_accept sd;
	RETVAL = scm_recv_msg (sock, &sd, sizeof(sd), &fd);
	if (!RETVAL) {
    		type = sd.type;
    		realm = sd.realm;
	}
    OUTPUT:
	type
	fd
	realm
	RETVAL


