package ebpf::constants::bpf_map_create_flags;

use strict;
use warnings;
use Exporter 'import';

our $VERSION = $ebpf::VERSION;

my %constants = (
    'BPF_F_NO_PREALLOC'     => 1 << 0,
    'BPF_F_NO_COMMON_LRU'   => 1 << 1,
    'BPF_F_NUMA_NODE'       => 1 << 2,
    'BPF_F_RDONLY'          => 1 << 3,
    'BPF_F_WRONLY'          => 1 << 4,
    'BPF_F_STACK_BUILD_ID'  => 1 << 5,
    'BPF_F_ZERO_SEED'       => 1 << 6,
    'BPF_F_RDONLY_PROG'     => 1 << 7,
    'BPF_F_WRONLY_PROG'     => 1 << 8,
    'BPF_F_CLONE'           => 1 << 9,
    'BPF_F_MMAPABLE'        => 1 << 10,
    'BPF_F_PRESERVE_ELEMS'  => 1 << 11,
    'BPF_F_INNER_MAP'       => 1 << 12,
    'BPF_F_LINK'            => 1 << 13,
    'BPF_F_PATH_FD'         => 1 << 14,
    'BPF_F_VTYPE_BTF_OBJ_FD'=> 1 << 15,
    'BPF_F_TOKEN_FD'        => 1 << 16,
    'BPF_F_SEGV_ON_FAULT'   => 1 << 17,
    'BPF_F_NO_USER_CONV'    => 1 << 18,
);

our @EXPORT_OK = keys %constants;
our %EXPORT_TAGS = (all => \@EXPORT_OK);

for my $name (@EXPORT_OK) {
    no strict 'refs';
    *{$name} = sub () { $constants{$name} };
}

1;