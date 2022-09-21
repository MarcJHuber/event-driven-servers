all: install

scm:
	cd ../../spawnd/perl && perl Makefile.PL && make && sudo make install

install: scm
	sudo install -m 0755 tactrace.pl /usr/local/bin/tactrace.pl

