use ExtUtils::MakeMaker;

WriteMakefile(
    NAME         => 'ebpf::c_bpf_loader',
    VERSION_FROM => 'lib/ebpf/c_bpf_loader.pm',
    LIBS         => [''],
    INC          => '-I.', 
    XS           => { 'lib/ebpf/c_bpf_loader.xs' => 'lib/ebpf/c_bpf_loader.c' },
    OBJECT       => '$(O_FILES)',  # link all the C files together
    INSTALLDIRS  => 'site',
);
