package Scm;

use strict;
use warnings;

require Exporter;
require DynaLoader;

our @ISA = qw(Exporter DynaLoader);
# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.
use constant {
	SCM_DONE => 0,
	SCM_KEEPALIVE => 1,
	SCM_MAY_DIE => 2,
	SCM_DYING => 3,
	SCM_BAD_CFG => 4,
	SCM_MAX => 5,
	SCM_ACCEPT => 6,
};

our @EXPORT_OK = qw(
	scm_recvmsg
	scm_sendmsg
	SCM_DONE
	SCM_KEEPALIVE
	SCM_MAY_DIE
	SCM_DYING
	SCM_BAD_CFG
	SCM_MAX
	SCM_ACCEPT
);
our $VERSION = '0.02';

bootstrap Scm $VERSION;

# Preloaded methods go here.

# Autoload methods go after __END__, and are processed by the autosplit program.

1;
__END__
# Below is the stub of documentation for your module. You better edit it!

