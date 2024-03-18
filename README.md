This is a collection of high-performance and scalable event-driven servers
(notably tac_plus-ng, tac_plus, ftpd, tcprelay). Please have a look at the
documentation for configuration details.

Issues can be reported via

  https://github.com/MarcJHuber/event-driven-servers/issues

Discussions can be starte via

  https://github.com/MarcJHuber/event-driven-servers/discussions

Home site is https://www.pro-bono-publico.de/projects/


Installation instructions
=========================

This software suite should compile quite fine on a variety of platforms,
e.g. current versions of Sun Solaris, FreeBSD, NetBSD, OpenBSD, DragonFly
BSD, Darwin, Linux and Cygwin. See the comments at the beginning of

  misc/sysconf.h

for a somewhat comprehensive list.

Unless you're trying to install the software on an unsupported system,
there shouldn't be any need to mess with the makefiles. If you do so,
you're on your own, and you'll better know what you're doing.

Build environment
-----------------

Required tools:

- A supported C compiler, plus linker. LLVM is fine, GCC will work too (but has issues with optimization, so that's disabled for now).
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
top-level "doc" director, and you can view it online at
https://www.pro-bono-publico.de/projects, too.

Support
=======

While I really appreciate that you're using the software I'd
very much prefer *not* to receive private support enquiries.

As already mentioned on the top of this page: Please direct support queries to GitHub discussions or issues:

  https://github.com/MarcJHuber/event-driven-servers/discussions
  https://github.com/MarcJHuber/event-driven-servers/issues

