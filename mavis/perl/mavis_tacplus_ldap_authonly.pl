#!/usr/bin/env perl
# For backwards compatibility only. Don't use for new installations.
use strict;
my $ldap_backend = $0;
$ldap_backend =~ s/_ldap_authonly\.pl$/_ldap.pl/;
$ENV{'LDAP_SERVER_TYPE'} = 'generic';
exec $ldap_backend $0, @ARGV or die "$ldap_backend: $!\n";

