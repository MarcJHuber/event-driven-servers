/*
 * quota.c
 * (C)1998-2011 by Marc Huber <Marc.Huber@web.de>
 *
 * $Id$
 *
 */

#include <sys/types.h>
#include "headers.h"
#include <unistd.h>
#include <fcntl.h>

static const char rcsid[] __attribute__((used)) = "$Id$";

static int lock(int);

void quota_add(struct context *ctx, long long q)
{
    int f;
    ssize_t i;
    char buffer[20];

    if (!ctx->quota_path)
	return;

    UNUSED_RESULT(setegid(real_uid));
    UNUSED_RESULT(seteuid(real_gid));
    f = open(ctx->quota_path, O_RDWR | O_CREAT | O_NOFOLLOW, 0644);
    if (f > -1) {
	if (!lock(f)) {
	    buffer[0] = 0;
	    i = read(f, buffer, sizeof(buffer) - 1);

	    if (i > 0)
		buffer[i] = 0;

	    sscanf(buffer, "%lld", &ctx->quota_ondisk);

	    if (q < 0 && ctx->quota_ondisk < -q)
		ctx->quota_ondisk = 0;
	    else
		ctx->quota_ondisk += q;

	    if (q) {
		lseek(f, 0, SEEK_SET);
		if (ftruncate(f, 0)) {
		    //FIXME
		}

		snprintf(buffer, sizeof(buffer), "%lld", ctx->quota_ondisk);
		if (write(f, buffer, strlen(buffer))) {
		    //FIXME
		}
	    }
	} else
	    logmsg("Updating quota file %s failed (%lld).", ctx->quota_path, q);
	close(f);
    }
    UNUSED_RESULT(setegid(ctx->gid));
    UNUSED_RESULT(seteuid(ctx->uid));
}

static int lock(int fn)
{
    struct flock fl;
    int i;
    sigset_t sig_set;

    Debug((DEBUG_LOCK, "+ %s (%d)\n", __func__, fn));

    fl.l_type = F_WRLCK;	/* exclusive lock */
    fl.l_whence = SEEK_SET;
    fl.l_len = 0;		/* lock whole file */
    fl.l_start = 0;

    sigemptyset(&sig_set);
    sigaddset(&sig_set, SIGALRM);
    sigprocmask(SIG_UNBLOCK, &sig_set, NULL);

    alarm(2);			/* wait at most 2 seconds for the lock */
    i = fcntl(fn, F_SETLKW, &fl);
    alarm(0);

    sigprocmask(SIG_BLOCK, &sig_set, NULL);

    Debug((DEBUG_LOCK, "- %s %s\n", __func__, i ? "FAILURE" : "SUCCESS"));
    return i;
}
