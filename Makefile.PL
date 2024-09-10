use ExtUtils::MakeMaker;

   WriteMakefile(
        NAME              => 'ebpf',
        VERSION_FROM      => 'lib/ebpf.pm',
        PREREQ_PM         => {
           'strict'      => 0,
           'warnings'    => 0,
           'Test::More'  => 0,
           'Exporter'    => 0,
           'Data::Dumper' => 0,
        },
        ABSTRACT_FROM     => 'lib/ebpf.pm',
        AUTHOR            => 'Takeru Hayasaka <hayatake396@gmail.com>',
        LICENSE           => 'perl',
        META_MERGE => {
            'meta-spec' => { version => 2 },
            resources => {
                repository => {
                    type => 'git',
                    url  => 'https://github.com/takehaya/perl-ebpf.git',
                    web  => 'https://github.com/takehaya/perl-ebpf',
                },
            },
        },
   );