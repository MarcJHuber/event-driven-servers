This is a collection of high-performance and scalable event-driven servers
(notably tac_plus-ng, but the legacy daemons tac_plus, ftpd and tcprelay
are still part of the GIT).

tac_plus-ng
===========

tac_plus-ng implements both TACACS+ (TCP, TLS) and RADIUS (UDP, TCP, DTLS, TLS),
with RADIUS support for PAP authentication and Downloadable ACLs.

Documentation:

  https://projects.pro-bono-publico.de/event-driven-servers/doc/tac_plus-ng.html

Sample configurations:

  https://github.com/MarcJHuber/event-driven-servers/tree/master/tac_plus-ng/sample

Support
=======

Issues can be reported via

  https://github.com/MarcJHuber/event-driven-servers/issues

Discussions can be started via

  https://github.com/MarcJHuber/event-driven-servers/discussions

Also, there's still the the legacy mailing list at

   event-driven-servers@googlegroups.com

Home site is https://www.pro-bono-publico.de/projects/

Bugs
====

Be prepared for issues. This is work-in-progress, so be prepared for unexpected bahavior. Don't use this in a production environment without testing. If it breaks, please file an issue. The non-helpful alternative would be to just keep the broken pieces, so please don't do that. 

Installation instructions
=========================

This software suite should compile quite fine on Linux, FreeBSD and OpenBSD.
Other platforms might be fine, too, but weren't recently tested.

Build environment
-----------------

Required tools:

- A supported C compiler, plus linker. LLVM is fine, GCC should work too (but I don't check this regulary, and it might have issues with optimization, so that's disabled for now).
- GNU make (version 3.79.1, unpatched,  recommended, others may or may
  not work).
- Perl
- Various development header files and libraries

Compile & Install
-----------------

Please run "./configure --help". It will output a list of supported
options. Then run ./configure with the appropriate arguments. After
that, run "make" to start the compilation process and "make install"
to install the compiled binaries.

Example:

````
./configure tac_plus-ng
make
sudo make install
````

You may actually omit the "configure" step if you're content with
the default build options, which are to compile everything and to
use all optional features your system supports at first glance.

If you don't care for the optional features (TLS support, C-ARES,
others), just run

````
./configure --minimum tac_plus-ng
make
sudo make install
````

Documentation
=============

The distribution comes with documentation located in the
top-level "doc" directory, and you can view it online at
https://www.pro-bono-publico.de/projects, too.

Support
=======

While I really appreciate that you're using the software I'd
very much prefer *not* to receive private support enquiries.

Please direct support queries to GitHub discussions, GitHub issues or the Google Group:

  https://github.com/MarcJHuber/event-driven-servers/discussions
  https://github.com/MarcJHuber/event-driven-servers/issues
  https://groups.google.com/g/event-driven-servers

