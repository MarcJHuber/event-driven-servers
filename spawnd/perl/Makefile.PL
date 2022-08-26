use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
   NAME         => 'Scm',
   VERSION_FROM => 'Scm.pm',
   INC          => '-I../..',
   LIB          => '-Lmavis',
   OBJECT	=> 'Scm.o',
);

